from flask import Flask, Blueprint, render_template, request, flash, session, redirect, url_for, current_app, jsonify, make_response
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

DB_CONFIGS = {
    'local': {
        'host': '10.0.30.32',
        'database': 'craveon',
        'user': 'root',
        'password': 'ClodAndrei8225',
    },
    'flask_connection': {
        'host': '192.168.1.65',
        'database': 'hotel_management',
        'user': 'root',
        'password': 'admin',
    }
}

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db_config():
    # Choose config based on environment variable, session, or other logic
    # Example: use ?db=flask_connection in query string to select remote DB
    db_key = request.args.get('db', 'local')
    return DB_CONFIGS.get(db_key, DB_CONFIGS['local'])

def connect_db():
    return mysql.connector.connect(**get_db_config())

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
        if request.headers.get('Accept') == 'application/json':
            return jsonify({'success': True, 'redirect': url_for("customer.index")})
        return make_header(redirect(url_for("customer.index")))

    # If logged in but not verified, go to verify page
    if session.get('user') and session.get('verified') is not True:
        if request.headers.get('Accept') == 'application/json':
            return jsonify({'success': True, 'redirect': url_for("customer.verify")})
        return make_header(redirect(url_for("customer.verify")))

    password_error = None
    errors = {}

    if request.method == "POST":
        if request.headers.get('Content-Type', '').startswith('application/json') or request.is_json:
            data = request.get_json(force=True)
            email = data.get("email", "").strip()
            password = data.get("password", "").strip()
        else:
            email = request.form.get("email", "").strip()
            password = request.form.get("password", "").strip()

        if not email:
            errors['email'] = "Email is required."
        else:
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, email):
                errors['email'] = "Invalid email format."
            else:
                local_part = email.split('@')[0]
                if re.fullmatch(r'\\d{3}', local_part):
                    errors['email'] = "Invalid email format. Email username cannot be exactly 3 digits."
                else:
                    conn = connect_db()
                    cursor = conn.cursor(dictionary=True)
                    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
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
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
            cursor.close()
            conn.close()

            if user and bcrypt.check_password_hash(user['password'], password):
                # ✅ Update status to 'Active'
                try:
                    conn = connect_db()
                    cursor = conn.cursor()
                    cursor.execute("UPDATE users SET status = 'Active' WHERE user_id = %s", (user['user_id'],))
                    conn.commit()
                except Exception as e:
                    print("Error updating login status:", e)
                finally:
                    cursor.close()
                    conn.close()

                session.pop('users', None)  # Clear any previous session
                session.permanent = True

                session["user"] = user['user_id']
                session["user_email"] = user['email']
                session["temp_user_id"] = user['user_id']
                session["verification_code"] = str(random.randint(100000, 999999))
                session["verified"] = False

                if send_verification_email(email, session["verification_code"]):
                    if request.headers.get('Accept') == 'application/json':
                        return jsonify({'success': True, 'redirect': url_for("customer.verify")})
                    return make_header(redirect(url_for("customer.verify")))
                else:
                    if request.headers.get('Accept') == 'application/json':
                        return jsonify({'success': False, 'message': "Failed to send verification email. Please try again."}), 500
                    flash("Failed to send verification email. Please try again.", "danger")
            else:
                password_error = "Incorrect password. Please try again."
                if request.headers.get('Accept') == 'application/json':
                    return jsonify({'success': False, 'message': password_error, 'email_error': errors.get('email')}), 401

        elif request.headers.get('Accept') == 'application/json':
            return jsonify({'success': False, 'message': password_error or errors.get('email'), 'email_error': errors.get('email'), 'password_error': password_error}), 400

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
            cursor.execute("UPDATE users SET status = 'Inactive' WHERE user_id = %s", (user_id,))
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

@customer.route('/api/checkin-guests', methods=['GET'])
def hotel_checkedin_guests():
    conn = mysql.connector.connect(
        host=DB_CONFIGS['flask_connection']['host'],
        user=DB_CONFIGS['flask_connection']['user'],
        password=DB_CONFIGS['flask_connection']['password'],
        database=DB_CONFIGS['flask_connection']['database']
    )
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT id AS booking_id, user_id, room_id, check_in_date, check_out_date, status
        FROM bookings
        WHERE status = 'checked_in'
    """)
    bookings = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify({"checked_in_bookings": bookings})

@customer.route('/api/hotel-food-order', methods=['POST'])
def hotel_guest_order():
    data = request.get_json(force=True)
    hotel_booking_id = data.get('hotel_booking_id')
    items = data.get('items', [])
    notes = data.get('notes', '')

    # 1. Check if booking is checked in
    hotel_conn = mysql.connector.connect(
        host=DB_CONFIGS['flask_connection']['host'],
        user=DB_CONFIGS['flask_connection']['user'],
        password=DB_CONFIGS['flask_connection']['password'],
        database=DB_CONFIGS['flask_connection']['database']
    )
    hotel_cursor = hotel_conn.cursor(dictionary=True)
    hotel_cursor.execute(
        "SELECT id, status FROM bookings WHERE id = %s", (hotel_booking_id,)
    )
    booking = hotel_cursor.fetchone()
    hotel_cursor.close()
    hotel_conn.close()

    if not booking or booking['status'] != 'checked_in':
        return jsonify({"success": False, "message": "Booking not found or not checked in"}), 400

    # 2. Place food order in craveon.orders
    if not items or not isinstance(items, list):
        return jsonify({"success": False, "message": "Items must be a non-empty list"}), 400

    try:
        craveon_conn = mysql.connector.connect(**DB_CONFIGS['local'])
        craveon_cursor = craveon_conn.cursor()
        total_amount = 0.0
        for item in items:
            craveon_cursor.execute("SELECT price FROM items WHERE item_id = %s", (item['item_id'],))
            row = craveon_cursor.fetchone()
            if not row:
                return jsonify({"success": False, "message": f"Item ID {item['item_id']} not found"}), 404
            price = float(row[0])
            total_amount += price * int(item['quantity'])

        craveon_cursor.execute("""
            INSERT INTO orders (user_id, total_amount, status, notes, hotel_booking_id, source)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            None,  # No user_id for external guest
            total_amount,
            'pending',
            notes,
            hotel_booking_id,
            'hotel'
        ))
        order_id = craveon_cursor.lastrowid

        for item in items:
            craveon_cursor.execute("""
                INSERT INTO order_items (order_id, item_id, quantity)
                VALUES (%s, %s, %s)
            """, (order_id, item['item_id'], item['quantity']))

        craveon_conn.commit()
        craveon_cursor.close()
        craveon_conn.close()

        return jsonify({
            "success": True,
            "order_id": order_id,
            "message": "Order placed successfully"
        }), 201

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


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
            
            response = redirect(url_for("customer.index"))
            return make_header(response)
        else:
            error_message = "Invalid verification code."

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
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, email):
                email_error = "Invalid email format."
            else:
                conn = connect_db()
                cursor = conn.cursor(dictionary=True)
                cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
                user = cursor.fetchone()
                cursor.close()
                conn.close()

                if not user:
                    email_error = "Email not found. Please check your email."
                else:
                    session["reset_user_id"] = user['user_id']
                    session["reset_email"] = email
                    session["reset_verification_code"] = str(random.randint(100000, 999999))

                    if send_verification_email(email, session["reset_verification_code"]):
                        response = redirect(url_for("customer.verify_reset"))
                        return make_header(response)
                    else:
                        email_error = "Failed to send verification email. Try again later."

        return make_header(make_response(render_template("forgotpassword.html", email_error=email_error)))

    return make_header(make_response(render_template("forgotpassword.html", email_error=email_error)))


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
                "UPDATE users SET password = %s WHERE user_id = %s",
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

        # Name validation
        if not firstname:
            errors['firstname'] = "First name is required."
        elif not firstname.isalpha():
            errors['firstname'] = "First name must contain only letters."
        elif len(firstname) < 3:
            errors['firstname'] = "First name must be at least 3 characters."
        elif ' ' in firstname:
            errors['firstname'] = "First name must not contain spaces."

        if middlename:
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

        # Email validation
        if not email:
            errors['email'] = "Email is required."
        else:
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, email):
                errors['email'] = "Invalid email format."
            else:
                conn = connect_db()
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
                existing_email = cursor.fetchone()
                cursor.close()
                conn.close()

                if existing_email:
                    errors['email'] = "Email already registered. Please use a different one."

        # Contact validation
        if not contact:
            errors['contact'] = "Contact number is required."
        elif not contact.isdigit():
            errors['contact'] = "Contact number must contain only digits."
        elif len(contact) != 11:
            errors['contact'] = "Contact number must be exactly 11 digits."
        else:
            conn = connect_db()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE contact = %s", (contact,))
            existing_contact = cursor.fetchone()
            cursor.close()
            conn.close()

            if existing_contact:
                errors['contact'] = "Contact number already registered. Please use a different one."

        # Password validation
        if not password:
            errors['password'] = "Password is required."
        elif len(password) < 8:
            errors['password'] = "Password must be at least 8 characters."

        if not confirm_password:
            errors['confirm_password'] = "Please confirm your password."
        elif password != confirm_password:
            errors['confirm_password'] = "Passwords do not match."

        # If there are errors, return to the form
        if errors:
            return render_template("signup.html", errors=errors)

        # Get and build address string
        region = request.form.get('region', '')
        province = request.form.get('province', '')
        municipality = request.form.get('municipality', '')
        barangay = request.form.get('barangay', '')
        full_address = f"{region}, {province}, {municipality}, {barangay}".strip(', ')

        # Hash password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Insert into users table
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO users (
                first_name, middle_name, last_name, email, contact, address, password
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (firstname, middlename, surname, email, contact, full_address, hashed_password))
        conn.commit()
        cursor.close()
        conn.close()

        return redirect(url_for('customer.login'))

    return render_template("signup.html", errors={})

@customer.route('/api/menu', methods=['GET'])
def api_menu():
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

    # Prepare JSON response data
    json_data = {
        "items": [],
        "categories": [{"category_id": c[0], "category_name": c[1]} for c in categories]
    }

    # Format items
    for item in items:
        item_id, name, price, img, category_name = item
        json_data["items"].append({
            "item_id": item_id,
            "name": name,
            "price": float(price),
            "image": base64.b64encode(img).decode('utf-8') if img else None,
            "category_name": category_name
        })

    return jsonify({
        'data': json_data
    }), 200

@customer.route('/Menu', methods=['GET'])
def menu():
    print("---- /Menu endpoint called ----")
    print("Session:", dict(session))
    print("Request headers:", dict(request.headers))
    print("Request args (query params):", dict(request.args))

    if 'user' not in session:
        if request.headers.get('Accept') == 'application/json':
            print("Not logged in: returning JSON error")
            return jsonify({'success': False, 'message': 'Not logged in'}), 401
        print("Not logged in: redirecting to login")
        return redirect(url_for('customer.login'))
    
    connection = connect_db()
    cursor = connection.cursor()

    # Fetch only active categories (is_archived = FALSE)
    cursor.execute("""
        SELECT category_id, category_name 
        FROM categories 
        WHERE is_archived = FALSE
        ORDER BY category_name
    """)
    categories = cursor.fetchall()

    # Fetch only active items (is_archived = FALSE) from active categories
    cursor.execute("""
        SELECT i.item_id, i.item_name, i.price, i.image, c.category_name 
        FROM items i
        JOIN categories c ON i.category_id = c.category_id
        WHERE i.is_archived = FALSE AND c.is_archived = FALSE
        ORDER BY i.item_name
    """)
    items = cursor.fetchall()
    connection.close()

    # Prepare data for JSON response
    json_data = {
        "items": [{
            "item_id": item[0],
            "name": item[1],
            "price": float(item[2]),
            "image": base64.b64encode(item[3]).decode('utf-8') if item[3] else None,
            "category_name": item[4]
        } for item in items],
        "categories": [{
            "category_id": cat[0],
            "category_name": cat[1]
        } for cat in categories]
    }

    # Return JSON if requested
    if 'application/json' in request.headers.get('Accept', ''):
        return jsonify({'data': json_data})
    
    # Render HTML template
    return render_template('menu.html', 
                         items=json_data["items"], 
                         categories=json_data["categories"])
    
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
            WHERE user_id = %s AND status != 'completed'
            ORDER BY ordered_at DESC LIMIT 1
        """, (customer_id,))
        order_row = cursor.fetchone()

        if order_row:
            order_id = order_row[0]
        else:
            # If no active order, create a new order
            cursor.execute("""
                INSERT INTO orders (user_id, total_amount, status)
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
    

@customer.route('/api/checkout', methods=['POST'])
def api_checkout():
    try:
        data = request.get_json()
        hotel_guest_info = data.get('hotel_guest_info')

        if hotel_guest_info and hotel_guest_info.get('is_hotel_order'):
            items = data.get('items', [])
            if not items:
                return jsonify({'success': False, 'message': 'Cart is empty'}), 400

            try:
                conn = connect_db()
                cursor = conn.cursor()

                total_amount = sum(float(item['price']) * int(item['quantity']) for item in items)

                hotel_guest_id = f"hotel_guest_{hotel_guest_info['booking_id']}"

                cursor.execute("""
                    INSERT INTO orders (user_id, total_amount, status)
                    VALUES (%s, %s, 'pending')
                    """, (hotel_guest_id, total_amount))
                
                order_id = cursor.lastrowid
                for item in items:
                    cursor.execute("""
                        INSERT INTO order_items (order_id, item_id, quantity)
                        VALUES (%s, %s, %s)
                    """, (order_id, item['item_id'], item['quantity']))
                conn.commit()
                cursor.close()
                conn.close()

                return jsonify({
                    "success": True,
                    "message": "Order placed successfully",
                    "order_id": order_id,
                    "hotel_guest_info": hotel_guest_info
                }), 200
            except Exception as e:
                return jsonify({'success': False, 'message': str(e)}), 500
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@customer.route('/checkout', methods=['POST'])
def checkout():
    try:
        items = request.json.get('items', [])
        if not items:
            return jsonify({'success': False, 'message': 'Cart is empty'}), 400

        print(f"[Checkout] Received items: {items}")

        customer_id = session['user']
        connection = connect_db()
        if not connection:
            print("[Checkout Error] Database connection failed")
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500

        cursor = connection.cursor()

        # Check for existing active order
        cursor.execute("""
            SELECT order_id FROM orders
            WHERE user_id = %s AND status != 'completed'
            ORDER BY ordered_at DESC LIMIT 1
        """, (customer_id,))
        order_row = cursor.fetchone()

        if order_row:
            order_id = order_row[0]
            print(f"[Checkout] Reusing existing order: {order_id}")
        else:
            try:
                total_amount = sum(float(item['price']) * int(item['quantity']) for item in items)
            except Exception as calc_error:
                print(f"[Checkout Error] Total calculation failed: {calc_error}")
                return jsonify({'success': False, 'message': 'Invalid item data'}), 400

            cursor.execute("""
                INSERT INTO orders (user_id, total_amount, status)
                VALUES (%s, %s, 'pending')
            """, (customer_id, total_amount))
            order_id = cursor.lastrowid
            print(f"[Checkout] New order created: {order_id}")

        for item in items:
            item_id = item.get('item_id')
            quantity = int(item.get('quantity', 1))

            if not item_id:
                print("[Checkout Error] Item ID missing in request")
                return jsonify({'success': False, 'message': 'Missing item ID'}), 400

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
                print(f"[Checkout] Updated item {item_id} quantity to {new_quantity}")
            else:
                cursor.execute("""
                    INSERT INTO order_items (order_id, item_id, quantity)
                    VALUES (%s, %s, %s)
                """, (order_id, item_id, quantity))
                print(f"[Checkout] Inserted item {item_id} x{quantity}")

        # Recalculate total from DB prices
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

        print(f"[Checkout] Order {order_id} finalized successfully.")
        return jsonify({'success': True, 'order_id': order_id})

    except Exception as e:
        print(f"[Checkout Error] {str(e)}")
        return jsonify({'success': False, 'message': f"Internal server error: {str(e)}"}), 500
    
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

        # Fetch user info
        cursor.execute("""
            SELECT user_id, first_name, middle_name, last_name, email, contact, address
            FROM users
            WHERE user_id = %s
        """, (customer_id,))
        cust_row = cursor.fetchone()

        if not cust_row:
            return jsonify({'error': 'Customer not found'}), 404

        customer = {
            'id': cust_row[0],
            'first_name': cust_row[1],
            'middle_name': cust_row[2],
            'last_name': cust_row[3],
            'email': cust_row[4],
            'contact': cust_row[5],
            'address': cust_row[6]
        }

        # Only fetch unpaid orders (payment_ss is NULL)
        cursor.execute("""
            SELECT order_id, ordered_at, payment_ss
            FROM orders
            WHERE user_id = %s AND payment_ss IS NULL
            ORDER BY ordered_at DESC
        """, (customer_id,))
        order_rows = cursor.fetchall()

        orders = []
        for order_id, ordered_at, payment_ss in order_rows:
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
                'payment_ss': payment_ss is not None,
                'items': items
            })

        return jsonify({'customer': customer, 'orders': orders})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

    finally:
        cursor.close()
        db.close()

        
@customer.route('/api/delete_order_item/<int:order_id>/<item_name>', methods=['DELETE'])
def delete_order_item(order_id, item_name):
    if 'user' not in session:
        return jsonify({'error': 'User not logged in'}), 401

    user_id = session['user']
    db = connect_db()
    cursor = db.cursor()

    try:
        # Verify the order belongs to the user
        cursor.execute("SELECT * FROM orders WHERE order_id = %s AND user_id = %s", (order_id, user_id))
        if not cursor.fetchone():
            return jsonify({'error': 'Order not found or not authorized'}), 404

        # Delete specific item from order_items
        cursor.execute("""
            DELETE oi FROM order_items oi
            JOIN items i ON oi.item_id = i.item_id
            WHERE oi.order_id = %s AND i.item_name = %s
        """, (order_id, item_name))

        # Recalculate new total
        cursor.execute("""
            SELECT SUM(i.price * oi.quantity)
            FROM order_items oi
            JOIN items i ON oi.item_id = i.item_id
            WHERE oi.order_id = %s
        """, (order_id,))
        new_total = cursor.fetchone()[0] or 0.00

        # Update total
        cursor.execute("UPDATE orders SET total_amount = %s WHERE order_id = %s", (new_total, order_id))

        db.commit()

        return jsonify({'message': 'Item deleted and total updated.'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

    finally:
        cursor.close()
        db.close()




@customer.route('/api/update_payment', methods=['POST'])
def update_payment():
    if 'user' not in session:
        return jsonify({'error': 'User not logged in'}), 401

    file = request.files.get('payment_proof')
    if not file or file.filename == '':
        return jsonify({'error': 'No file uploaded'}), 400

    image_bytes = file.read()

    if not allowed_file(file.filename):  
        return jsonify({'error': 'Invalid file type.'}), 400


    try:
        db = connect_db()
        cursor = db.cursor()
        customer_id = session['user']

        payment_base64 = base64.b64encode(image_bytes).decode('utf-8')

        cursor.execute("""
            SELECT order_id FROM orders
            WHERE user_id = %s AND status = 'Pending'
            ORDER BY ordered_at DESC LIMIT 1
        """, (customer_id,))
        row = cursor.fetchone()
        if not row:
            return jsonify({'error': 'No order found to update'}), 404

        order_id = row[0]
        cursor.execute("""
            UPDATE orders SET payment_ss = %s WHERE order_id = %s
        """, (payment_base64, order_id))
        db.commit()

        cursor.execute("INSERT INTO orders (user_id, total_amount) VALUES (%s, 0.00)", (customer_id,))
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

        cursor.execute("""
            SELECT user_id, first_name, middle_name, last_name, email, contact, address, user_img
            FROM users
            WHERE user_id = %s
        """, (customer_id,))
        cust_row = cursor.fetchone()

        if not cust_row:
            return jsonify({'error': 'Customer not found'}), 404

        full_name = f"{cust_row[1]}{' ' + cust_row[2] if cust_row[2] else ''} {cust_row[3]}".strip()

        user_img = None
        if cust_row[7]:
            user_img = base64.b64encode(cust_row[7]).decode('utf-8') if isinstance(cust_row[7], bytes) else cust_row[7]

        customer = {
            'id': cust_row[0],
            'name': full_name,
            'email': cust_row[4],
            'contact': cust_row[5],
            'address': cust_row[6],
            'user_img': user_img
        }

        cursor.execute("""
            SELECT order_id, ordered_at, total_amount, status, reviewed
            FROM orders
            WHERE user_id = %s
            ORDER BY ordered_at DESC
        """, (customer_id,))
        order_rows = cursor.fetchall()

        if not order_rows:
            return jsonify({'customer': customer, 'orders': []})

        orders = []
        for order_id, ordered_at, total_amount, status, reviewed in order_rows[1:]:
            cursor.execute("""
                SELECT i.item_name, i.price, i.image, oi.quantity
                FROM order_items oi
                JOIN items i ON oi.item_id = i.item_id
                WHERE oi.order_id = %s
            """, (order_id,))
            item_rows = cursor.fetchall()

            items = []
            for name, price, image, quantity in item_rows:
                if image and isinstance(image, bytes):
                    image = base64.b64encode(image).decode('utf-8')
                items.append({
                    'name': name,
                    'price': float(price),
                    'image': image,
                    'quantity': quantity
                })

            # If reviewed is True, override status
            if reviewed:
                status = 'Reviewed'

            orders.append({
                'order_id': order_id,
                'ordered_at': ordered_at.strftime('%Y-%m-%d %H:%M:%S'),
                'total_amount': float(total_amount),
                'status': status,
                'items': items,
                'reviewed': reviewed
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
            SELECT user_id, 'Your Order has been Cancelled', 'Your order has been successfully cancelled.'
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

        
@customer.route('/Account')
def account():
    if 'user' not in session:
        return redirect(url_for('customer.login'))

    customer_id = session['user']
    conn = connect_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE user_id = %s", (customer_id,))
    customer = cursor.fetchone()
    cursor.close()
    conn.close()

    return render_template('account.html', customer=customer)

@customer.route('/upload_image', methods=['POST'])
def upload_image():
    if 'user' not in session:
        flash('You must be logged in to upload an image.', 'error')
        return redirect(url_for('customer.login'))

    file = request.files.get('profile_image')
    if not file or file.filename == '':
        flash('No image uploaded.', 'error')
        return redirect(url_for('customer.account'))

    image_data = base64.b64encode(file.read()).decode('utf-8')

    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET user_img = %s WHERE user_id = %s", (image_data, session['user']))
    conn.commit()
    cursor.close()
    conn.close()

    flash('Profile image updated successfully.', 'success')
    return redirect(url_for('customer.account'))

@customer.route('/api/submit_review', methods=['POST'])
def submit_review():
    data = request.get_json()
    order_id = data.get('order_id')
    rating = data.get('rating')
    comment = data.get('comment', '').strip()

    if not order_id or not rating:
        return jsonify({'error': 'Missing data'}), 400

    db = connect_db()
    cursor = db.cursor()

    cursor.execute("SELECT reviewed FROM orders WHERE order_id = %s", (order_id,))
    row = cursor.fetchone()
    if not row:
        return jsonify({'error': 'Order not found'}), 404
    if row[0]:
        return jsonify({'error': 'You have already reviewed this order'}), 400

    cursor.execute("INSERT INTO reviews (order_id, rating, comment) VALUES (%s, %s, %s)",
                (order_id, rating, comment))
    cursor.execute("UPDATE orders SET reviewed = 1 WHERE order_id = %s", (order_id,))
    db.commit()

    return jsonify({'message': 'Thank you for your review!'})

@customer.route('/update_account', methods=['POST'])
def update_account():
    if 'user' not in session:
        return redirect(url_for('customer.login'))

    user_id = session['user']
    first_name = request.form.get('first_name', '').strip()
    middle_name = request.form.get('middle_name', '').strip()
    last_name = request.form.get('last_name', '').strip()
    email = request.form.get('email', '').strip()
    contact = request.form.get('contact', '').strip()

    region = request.form.get('region', '').strip()
    province = request.form.get('province', '').strip()
    municipality = request.form.get('municipality', '').strip()
    barangay = request.form.get('barangay', '').strip()

    # Combine full address
    address = f"{region}, {province}, {municipality}, {barangay}"

    # Validation
    errors = []
    if not first_name:
        errors.append("First name is required.")
    if not last_name:
        errors.append("Last name is required.")
    if not email:
        errors.append("Email is required.")
    elif not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        errors.append("Invalid email format.")
    if not contact:
        errors.append("Contact number is required.")
    elif not contact.isdigit() or len(contact) != 11:
        errors.append("Contact number must be 11 digits.")
    if not region or not province or not municipality or not barangay:
        errors.append("Complete address is required.")

    if errors:
        for error in errors:
            flash(error, 'error')
        return redirect(url_for('customer.account'))

    # Update database
    db = connect_db()
    cursor = db.cursor()

    cursor.execute("""
        UPDATE users SET 
            first_name = %s,
            middle_name = %s,
            last_name = %s,
            email = %s,
            contact = %s,
            address = %s
        WHERE user_id = %s
    """, (first_name, middle_name, last_name, email, contact, address, user_id))

    db.commit()
    cursor.close()
    db.close()

    flash('Account updated successfully!', 'success')
    return redirect(url_for('customer.account'))

