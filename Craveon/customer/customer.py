from flask import Flask, Blueprint, render_template, request, flash, session, redirect, url_for, current_app, jsonify, make_response, json
import mysql.connector
import base64
from datetime import datetime
import re
import random
from flask_mail import Message
from flask_bcrypt import Bcrypt


customer = Blueprint('customer', __name__, template_folder="template") 

bcrypt = Bcrypt()

def make_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

db_config = {
    'host':'localhost',
    'database':'craveon',
    'user':'root',
    'password':'haharaymund',
}

def connect_db():
    return mysql.connector.connect(**db_config)
conn = connect_db()
cursor = conn.cursor()

@customer.app_template_filter('b64encode')
def b64encode_filter(data):
    return base64.b64encode(data).decode('utf-8') if data else ''

@customer.route("/")
def index():
    # User must be logged in AND verified
    if 'user' not in session:
        return make_header(redirect(url_for("customer.login")))

    if session.get("verified") is not True:
        return make_header(redirect(url_for("customer.verify")))

    # Render index with no-cache
    response = make_response(render_template("cindex.html"))
    return make_header(response)


@customer.route('/login', methods=['GET', 'POST'])
def login():
    # Prevent accessing login if already logged in and verified
    if session.get('user') and session.get('verified') is True:
        return make_header(redirect(url_for("customer.index")))

    # If logged in but not verified, go to verify page
    if session.get('user') and session.get('verified') is not True:
        return make_header(redirect(url_for("customer.verify")))

    email_error = None
    password_error = None
    errors = {}

    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()

        # Email validation
        if not email:
            errors['email'] = "Email is required."
        else:
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, email):
                errors['email'] = "Invalid email format."
            else:
                local_part = email.split('@')[0]
                if re.fullmatch(r'\d{3}', local_part):
                    errors['email'] = "Invalid email format. Email username cannot be exactly 3 digits."
                else:
                    conn = connect_db()
                    cursor = conn.cursor(dictionary=True)
                    cursor.execute("SELECT * FROM customers WHERE email = %s", (email,))
                    existing_user = cursor.fetchone()
                    cursor.close()
                    conn.close()

                    if not existing_user:
                        errors['email'] = "Email not found. Please check your email or register."

        # Password validation
        if not password:
            password_error = "Password is required."

        # Proceed if no errors
        if not errors and not password_error:
            conn = connect_db()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM customers WHERE email = %s", (email,))
            user = cursor.fetchone()
            cursor.close()
            conn.close()

            if user and bcrypt.check_password_hash(user['password'], password):
                # ✅ Update status to 'Active'
                try:
                    conn = connect_db()
                    cursor = conn.cursor()
                    cursor.execute("UPDATE customers SET status = 'Active' WHERE customer_id = %s", (user['customer_id'],))
                    conn.commit()
                except Exception as e:
                    print("Error updating login status:", e)
                finally:
                    cursor.close()
                    conn.close()

                session.pop('users', None)  # Clear any previous session
                session.permanent = True

                session["user"] = user['customer_id']
                session["user_email"] = user['email']
                session["temp_user_id"] = user['customer_id']
                session["verification_code"] = str(random.randint(100000, 999999))
                session["verified"] = False

                if send_verification_email(email, session["verification_code"]):
                    return make_header(redirect(url_for("customer.verify")))
                else:
                    flash("Failed to send verification email. Please try again.", "danger")
            else:
                password_error = "Incorrect password. Please try again."

    response = make_response(render_template(
        "clogin.html",
        email_error=errors.get('email'),
        password_error=password_error
    ))
    return make_header(response)




def send_verification_email(email, code):
    try:
        mail = current_app.extensions.get('mail')

        if not mail:
            return False

        message = Message(
            subject="Your Verification Code",
            recipients=[email],
            sender=current_app.config['MAIL_USERNAME'],
            body=f"Your verification code is: {code}"
        )

        mail.send(message)
        return True
    except Exception as e:
        print(f"FAILED TO SEND EMAIL: {str(e)}")
        return False


@customer.route("/logout", methods=["GET"])
def logout():
    if 'user' in session:
        user_id = session['user'] # adjust based on how you store session info

        try:
            conn = connect_db()
            cursor = conn.cursor()
            # Update status to Inactive
            cursor.execute("UPDATE customers SET status = 'Inactive' WHERE customer_id = %s", (user_id,))
            conn.commit()
        except Exception as e:
            print("Error updating status:", e)
        finally:
            cursor.close()
            conn.close()

        session.pop('user', None)

    response = make_response(redirect(url_for('customer.index')))
    response = make_header(response)
    return response


@customer.route("/Verify-Account", methods=['GET', 'POST'])
def verify():
    if session.get("verified") is True:
        return make_header(redirect(url_for("customer.index")))

    if 'user' not in session or 'verification_code' not in session:
        return make_header(redirect(url_for("customer.login")))

    error_message = None

    if request.method == "POST":
        entered_code = "".join([
            request.form.get("code1", ""), request.form.get("code2", ""),
            request.form.get("code3", ""), request.form.get("code4", ""),
            request.form.get("code5", ""), request.form.get("code6", "")
        ])

        if entered_code == session.get("verification_code"):
            session["verified"] = True
            session.pop("verification_code", None)
            
            # ✅ Redirect with no-cache so back button won’t work
            response = redirect(url_for("customer.index"))
            return make_header(response)
        else:
            error_message = "Invalid verification code."

    # ✅ Final response with no cache (so browser won’t keep it)
    response = make_response(render_template("verify.html", error_message=error_message))
    return make_header(response)


@customer.route('/Forgot-Password', methods=['GET', 'POST'])
def forgot_password():  
    if 'user' in session or 'reset_user_id' in session:
        response = redirect(url_for('customer.verify_reset'))
        return make_header(response)

    email_error = None

    if request.method == "POST":
        email = request.form.get("email", "").strip()

        if not email:
            email_error = "Email is required."
        else:
            # Check if email format is valid
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, email):
                email_error = "Invalid email format."
            else:
                # Proceed to check if the email exists in the database
                conn = connect_db()
                cursor = conn.cursor(dictionary=True)
                cursor.execute("SELECT * FROM customers WHERE email = %s", (email,))
                user = cursor.fetchone()
                cursor.close()
                conn.close()

                if not user:
                    email_error = "Email not found. Please check your email."
                else:
                    # ✅ Save reset session data
                    session["reset_user_id"] = user['customer_id']
                    session["reset_email"] = email
                    session["reset_verification_code"] = str(random.randint(100000, 999999))

                    if send_verification_email(email, session["reset_verification_code"]):
                        response = redirect(url_for("customer.verify_reset"))
                        return make_header(response)
                    else:
                        email_error = "Failed to send verification email. Try again later."

        response = make_response(render_template("forgotpassword.html", email_error=email_error))
        return make_header(response)


@customer.route('/Verify-Reset', methods=['GET', 'POST'])
def verify_reset():
    if "user" in session:
        response = redirect(url_for('customer.login'))
        return make_header(response)

    if "reset_verification_code" not in session or "reset_user_id" not in session:
        response = redirect(url_for('customer.forgot_password'))
        return make_header(response)

    error_message = None

    if request.method == "POST":
        entered_code = "".join([
            request.form.get("code1", ""), request.form.get("code2", ""),
            request.form.get("code3", ""), request.form.get("code4", ""),
            request.form.get("code5", ""), request.form.get("code6", "")
        ])

        if entered_code == session.get("reset_verification_code"):
            session.pop("reset_verification_code", None)
            response = redirect(url_for("customer.reset_password"))
            return make_header(response)
        else:
            error_message = "Invalid verification code."

    # Apply no-cache headers to prevent back navigation
    response = make_response(render_template("verifyreset.html", error_message=error_message))
    return make_header(response)


@customer.route('/Reset-Password', methods=['GET', 'POST'])
def reset_password():
    if "reset_user_id" not in session:
        response = redirect(url_for("customer.login"))
        return make_header(response)

    password_error = None

    if request.method == "POST":
        new_password = request.form.get("new_password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        if not new_password or not confirm_password:
            password_error = "Both password fields are required."
        elif new_password != confirm_password:
            password_error = "Passwords do not match."
        elif len(new_password) < 8:
            password_error = "Password must be at least 8 characters long."
        else:
            # Hash the password before saving
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

            # Update password in database
            conn = connect_db()
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE customers SET password = %s WHERE customer_id = %s",
                (hashed_password, session["reset_user_id"])
            )
            conn.commit()
            cursor.close()
            conn.close()

            # Clear session
            session.pop("reset_user_id", None)

            # Redirect to login with no-cache headers
            response = redirect(url_for("customer.login"))
            return make_header(response)

    # Prevent caching on GET render
    response = make_response(render_template("resetpassword.html", password_error=password_error))
    return make_header(response)



@customer.route('/SignUp', methods=['GET', 'POST'])
def signup():
    errors = {}

    if request.method == 'POST':
        firstname = request.form.get('firstname', '').strip()
        middlename = request.form.get('middlename', '').strip()
        surname = request.form.get('surname', '').strip()
        email = request.form.get('email', '').strip()
        contact = request.form.get('contact', '').strip()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm-password', '').strip()

        # Name Validation
        if not firstname:
            errors['firstname'] = "First name is required."
        elif not firstname.isalpha():
            errors['firstname'] = "First name must contain only letters."
        elif len(firstname) < 3:
            errors['firstname'] = "First name must be at least 3 characters."
        elif ' ' in firstname:
            errors['firstname'] = "First name must not contain spaces."

        if not middlename.isalpha():
            errors['middlename'] = "Middle name must contain only letters."
        elif len(middlename) < 3:
            errors['middlename'] = "Middle name must be at least 3 characters."
        elif ' ' in middlename:
            errors['middlename'] = "Middle name must not contain spaces."

        if not surname:
            errors['surname'] = "Surname is required."
        elif not surname.isalpha():
            errors['surname'] = "Surname must contain only letters."
        elif len(surname) < 3:
            errors['surname'] = "Surname must be at least 3 characters."
        elif ' ' in surname:
            errors['surname'] = "Surname must not contain spaces."


        # Email Validation
        if not email:
            errors['email'] = "Email is required."
        else:
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, email):
                errors['email'] = "Invalid email format."
            else:
                conn = connect_db()
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM customers WHERE email = %s", (email,))
                existing_email = cursor.fetchone()
                cursor.close()
                conn.close()

                if existing_email:
                    errors['email'] = "Email already registered. Please use a different one."

        # Contact Validation
        if not contact:
            errors['contact'] = "Contact number is required."
        elif not contact.isdigit():
            errors['contact'] = "Contact number must contain only digits."
        elif len(contact) != 11:
            errors['contact'] = "Contact number must be exactly 11 digits."
        else:
            conn = connect_db()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM customers WHERE contact = %s", (contact,))
            existing_contact = cursor.fetchone()
            cursor.close()
            conn.close()

            if existing_contact:
                errors['contact'] = "Contact number already registered. Please use a different one."

        # Password Validation
        if not password:
            errors['password'] = "Password is required."
        elif len(password) < 8:
            errors['password'] = "Password must be at least 8 characters."

        if not confirm_password:
            errors['confirm_password'] = "Please confirm your password."
        elif password != confirm_password:
            errors['confirm_password'] = "Passwords do not match."

        if errors:
            return render_template("signup.html", errors=errors)

        # Create full name
        full_name = f"{firstname} {middlename} {surname}".strip()  # Strip middle name if empty
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Get address values (region, province, municipality, barangay) from the form
        region = request.form.get('region', '')
        province = request.form.get('province', '')
        municipality = request.form.get('municipality', '')
        barangay = request.form.get('barangay', '')

        # Concatenate address values into one string
        full_address = f"{region}, {province}, {municipality}, {barangay}".strip(", ")

        conn = connect_db()
        cursor = conn.cursor()

        # Insert into 'customer' table (name, address, email, contact, password)
        cursor.execute(
            "INSERT INTO customers (full_name, email, contact, address, password) VALUES (%s, %s, %s, %s, %s)",
            (full_name, email, contact, full_address, hashed_password)
        )
        conn.commit()
        cursor.close()
        conn.close()

        # After successful sign up, redirect to login page
        return redirect(url_for('customer.login'))

    return render_template("signup.html", errors={})

@customer.route('/Menu')
def menu():
    if 'user' not in session:
        return redirect(url_for('customer.login'))

    connection = connect_db()
    cursor = connection.cursor()

    # Fetch items with category name
    cursor.execute("""
        SELECT i.item_id, i.item_name, i.price, i.image, c.category_name 
        FROM items i
        JOIN categories c ON i.category_id = c.category_id
    """)
    items = cursor.fetchall()

    # Fetch categories
    cursor.execute("SELECT category_id, category_name FROM categories")
    categories = cursor.fetchall()

    connection.close()

    # Format items (encode images)
    formatted_items = []
    for item_id, name, price, img, category_name in items:
        if isinstance(img, bytes):
            img_base64 = base64.b64encode(img).decode('utf-8')
        else:
            img_base64 = None
        formatted_items.append((item_id, name, price, img_base64, category_name))

    return render_template('menu.html', items=formatted_items, categories=categories)

@customer.route('/buy-now', methods=['POST'])
def buy_now():
    if 'user' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401

    try:
        item_id = request.json.get('item_id')
        quantity = int(request.json.get('quantity', 1))
        price = float(request.json.get('price'))

        if not item_id or not price:
            return jsonify({'success': False, 'message': 'Missing item ID or price'}), 400

        customer_id = session['user']
        total_amount = price * quantity

        connection = connect_db()
        cursor = connection.cursor()

        # Check if there's an active order for the customer (not completed yet)
        cursor.execute("""
            SELECT order_id FROM orders
            WHERE customer_id = %s AND status != 'completed'
            ORDER BY ordered_at DESC LIMIT 1
        """, (customer_id,))
        order_row = cursor.fetchone()

        if order_row:
            order_id = order_row[0]
        else:
            # If no active order, create a new order
            cursor.execute("""
                INSERT INTO orders (customer_id, total_amount, status)
                VALUES (%s, %s, 'pending')
            """, (customer_id, total_amount))
            order_id = cursor.lastrowid

        # Now that we have a valid order_id, insert the item
        cursor.execute("""
            SELECT quantity FROM order_items
            WHERE order_id = %s AND item_id = %s
        """, (order_id, item_id))
        item_row = cursor.fetchone()

        if item_row:
            # If item exists, update the quantity
            new_quantity = item_row[0] + quantity
            cursor.execute("""
                UPDATE order_items
                SET quantity = %s
                WHERE order_id = %s AND item_id = %s
            """, (new_quantity, order_id, item_id))
        else:
            # If item doesn't exist, add it as a new item
            cursor.execute("""
                INSERT INTO order_items (order_id, item_id, quantity)
                VALUES (%s, %s, %s)
            """, (order_id, item_id, quantity))

        # Update total amount in orders table to reflect changes
        cursor.execute("""
            UPDATE orders
            SET total_amount = (SELECT SUM(i.price * oi.quantity)
                FROM order_items oi
                JOIN items i ON oi.item_id = i.item_id
                WHERE oi.order_id = %s)
            WHERE order_id = %s
        """, (order_id, order_id))

        connection.commit()
        cursor.close()
        connection.close()

        return jsonify({'success': True, 'message': 'Order placed successfully', 'order_id': order_id})

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    
@customer.route('/checkout', methods=['POST'])
def checkout():
    if 'user' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401

    try:
        items = request.json.get('items', [])
        if not items:
            return jsonify({'success': False, 'message': 'Cart is empty'}), 400

        customer_id = session['user']
        connection = connect_db()
        cursor = connection.cursor()

        # Check for an existing active order
        cursor.execute("""
            SELECT order_id FROM orders
            WHERE customer_id = %s AND status != 'completed'
            ORDER BY ordered_at DESC LIMIT 1
        """, (customer_id,))
        order_row = cursor.fetchone()

        if order_row:
            order_id = order_row[0]
        else:
            # Calculate total
            total_amount = sum(float(item['price']) * int(item['quantity']) for item in items)
            cursor.execute("""
                INSERT INTO orders (customer_id, total_amount, status)
                VALUES (%s, %s, 'pending')
            """, (customer_id, total_amount))
            order_id = cursor.lastrowid

        for item in items:
            item_id = item.get('item_id')
            quantity = int(item.get('quantity', 1))

            # Check if item already exists in this order
            cursor.execute("""
                SELECT quantity FROM order_items
                WHERE order_id = %s AND item_id = %s
            """, (order_id, item_id))
            existing = cursor.fetchone()

            if existing:
                new_quantity = existing[0] + quantity
                cursor.execute("""
                    UPDATE order_items
                    SET quantity = %s
                    WHERE order_id = %s AND item_id = %s
                """, (new_quantity, order_id, item_id))
            else:
                cursor.execute("""
                    INSERT INTO order_items (order_id, item_id, quantity)
                    VALUES (%s, %s, %s)
                """, (order_id, item_id, quantity))

        # Recalculate total amount
        cursor.execute("""
            UPDATE orders
            SET total_amount = (
                SELECT SUM(i.price * oi.quantity)
                FROM order_items oi
                JOIN items i ON oi.item_id = i.item_id
                WHERE oi.order_id = %s
            )
            WHERE order_id = %s
        """, (order_id, order_id))

        connection.commit()
        cursor.close()
        connection.close()

        return jsonify({'success': True, 'order_id': order_id})

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    
@customer.route('/Orders')
def orders():
    return render_template('orders.html')
    
@customer.route('/api/orders', methods=['GET'])
def api_orders():
    if 'user' not in session:
        return jsonify({'error': 'User not logged in'}), 401

    db = connect_db()
    cursor = db.cursor()

    try:
        customer_id = session['user']

        # Get customer info
        cursor.execute("""
            SELECT customer_id, full_name, email, contact, address
            FROM customers
            WHERE customer_id = %s
        """, (customer_id,))
        cust_row = cursor.fetchone()

        if not cust_row:
            return jsonify({'error': 'Customer not found'}), 404

        customer = {
            'id': cust_row[0],
            'name': cust_row[1],
            'email': cust_row[2],
            'contact': cust_row[3],
            'address': cust_row[4]
        }

        # Get all orders for the customer
        cursor.execute("""
            SELECT order_id, ordered_at
            FROM orders
            WHERE customer_id = %s
            ORDER BY ordered_at DESC
        """, (customer_id,))
        order_rows = cursor.fetchall()

        if not order_rows:
            return jsonify({'customer': customer, 'orders': []})

        orders = []
        for order_id, ordered_at in order_rows:
            # Get items for each order
            cursor.execute("""
                SELECT i.item_name, i.price, i.image, oi.quantity
                FROM order_items oi
                JOIN items i ON oi.item_id = i.item_id
                WHERE oi.order_id = %s
            """, (order_id,))
            item_rows = cursor.fetchall()

            items = []
            for row in item_rows:
                items.append({
                    'name': row[0],
                    'price': float(row[1]),
                    'image': base64.b64encode(row[2]).decode('utf-8') if row[2] else None,
                    'quantity': row[3]
                })

            orders.append({
                'order_id': order_id,
                'ordered_at': ordered_at.strftime('%Y-%m-%d %H:%M'),
                'items': items
            })

        return jsonify({'customer': customer, 'orders': orders})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

    finally:
        cursor.close()
        db.close()

import base64
from werkzeug.utils import secure_filename

# Allowed file extensions for images
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@customer.route('/api/update_payment', methods=['POST'])
def update_payment():
    if 'user' not in session:
        return jsonify({'error': 'User not logged in'}), 401

    if 'payment_proof' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['payment_proof']

    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type. Only JPG, JPEG, PNG, and GIF files are allowed.'}), 400

    try:
        db = connect_db()
        cursor = db.cursor()
        customer_id = session['user']

        # Read and encode the file in Base64
        image_bytes = file.read()
        payment_base64 = base64.b64encode(image_bytes).decode('utf-8')

        # Get the most recent order
        cursor.execute("""
            SELECT order_id FROM orders
            WHERE customer_id = %s
            ORDER BY ordered_at DESC
            LIMIT 1
        """, (customer_id,))
        row = cursor.fetchone()

        if not row:
            return jsonify({'error': 'No order found to update payment'}), 404

        order_id = row[0]

        # Update order with payment screenshot
        cursor.execute("""
            UPDATE orders
            SET payment_ss = %s
            WHERE order_id = %s
        """, (payment_base64, order_id))
        db.commit()

        # Create new empty order
        cursor.execute("""
            INSERT INTO orders (customer_id)
            VALUES (%s)
        """, (customer_id,))
        db.commit()

        return jsonify({'redirect_url': url_for('customer.thankyou')})

    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500

    finally:
        cursor.close()
        db.close()


        
@customer.route('/thankyou')
def thankyou():
    return render_template('thankyou.html')

@customer.route('/MyOrders')
def myorders():
        return render_template('myorders.html')
    
@customer.route('/api/myorders', methods=['GET'])
def my_orders():
    if 'user' not in session:
        return jsonify({'error': 'User not logged in'}), 401

    db = connect_db()
    cursor = db.cursor()

    try:
        customer_id = session['user']

        # Get customer info
        cursor.execute("""
            SELECT customer_id, full_name, email, contact, address
            FROM customers
            WHERE customer_id = %s
        """, (customer_id,))
        cust_row = cursor.fetchone()

        if not cust_row:
            return jsonify({'error': 'Customer not found'}), 404

        customer = {
            'id': cust_row[0],
            'name': cust_row[1],
            'email': cust_row[2],
            'contact': cust_row[3],
            'address': cust_row[4]
        }

        # Get all orders for the customer ordered by the latest first
        cursor.execute("""
            SELECT order_id, ordered_at, total_amount, status
            FROM orders
            WHERE customer_id = %s
            ORDER BY ordered_at DESC
        """, (customer_id,))
        order_rows = cursor.fetchall()

        if not order_rows:
            return jsonify({'customer': customer, 'orders': []})

        # Skip the most recent order (the first order)
        orders = []
        for order_id, ordered_at, total_amount, status in order_rows[1:]:
            cursor.execute("""
                SELECT i.item_name, i.price, i.image, oi.quantity
                FROM order_items oi
                JOIN items i ON oi.item_id = i.item_id
                WHERE oi.order_id = %s
            """, (order_id,))
            item_rows = cursor.fetchall()

            items = []
            for item_name, price, image, quantity in item_rows:
                items.append({
                    'name': item_name,
                    'price': float(price),
                    'image': base64.b64encode(image).decode('utf-8') if image else None,
                    'quantity': quantity
                })

            orders.append({
                'order_id': order_id,
                'ordered_at': ordered_at.strftime('%Y-%m-%d %H:%M'),
                'total_amount': total_amount,
                'status': status,
                'items': items
            })

        return jsonify({'customer': customer, 'orders': orders})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

    finally:
        cursor.close()
        db.close()


@customer.route('/api/cancel_order', methods=['POST'])
def cancel_order():
    data = request.get_json()
    order_id = data.get('order_id')
    cancellation_reason = data.get('cancellation_reason')

    if not order_id or not cancellation_reason:
        return jsonify({'error': 'Order ID and cancellation reason are required'}), 400

    try:
        # Connect to the database and update the order status and reason
        db = connect_db()
        cursor = db.cursor()

        cursor.execute("""
            UPDATE orders
            SET status = 'Cancelled', cancellation_reason = %s
            WHERE order_id = %s
        """, (cancellation_reason, order_id))

        db.commit()

        if cursor.rowcount == 0:
            return jsonify({'error': 'Order not found'}), 404

        cursor.execute("""
            INSERT INTO notifications (customer_id, title, message)
            SELECT customer_id, 'Your Order has been Cancelled', 'Your order has been successfully cancelled.'
            FROM orders
            WHERE order_id = %s
        """, (order_id,))
        db.commit()

        return jsonify({'message': 'Order cancelled successfully'}), 200

    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500

    finally:
        cursor.close()
        db.close()