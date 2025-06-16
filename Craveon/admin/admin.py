import base64
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify, make_response
import mysql.connector
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename



admin = Blueprint('admin', __name__, template_folder="template")
bcrypt = Bcrypt()

db_config = {
    'host': 'localhost',
    'database': 'craveon',
    'user': 'root',
    'password': 'haharaymund',
}

ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def make_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, proxy-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

def connect_db():
    return mysql.connector.connect(**db_config)

@admin.app_template_filter('b64encode')
def b64encode_filter(data):
    return base64.b64encode(data).decode('utf-8') if data else ''

@admin.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('admin.login'))
    return render_template('index.html')



@admin.route('/login', methods=['GET', 'POST'])
def login():
    if 'user' in session:
        return redirect(url_for('admin.index'))

    emailmsg = ''
    passwordmsg = ''
    msg = ''
    
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if email != 'admin123@gmail.com':
            emailmsg = 'Email is incorrect!'

        if password != 'admin':
            passwordmsg = 'Password is incorrect!'

        if not emailmsg and not passwordmsg:
            try:
                connection = mysql.connector.connect(**db_config)
                cursor = connection.cursor()
                cursor.execute("INSERT INTO admin (username, password) VALUES(%s, %s)", (email, password))
                connection.commit()
                session['user'] = email
                return redirect(url_for('admin.index'))
            except mysql.connector.Error as e:
                msg = f"Adding data failed! Error: {str(e)}"
            finally:
                cursor.close()
                connection.close()
        else:
            msg = emailmsg or passwordmsg

    response = make_response(render_template('login.html', msg=msg, emailmsg=emailmsg, passwordmsg=passwordmsg))
    return make_header(response)

@admin.route('/logout')
def logout():
    session.pop('user', None)
    response = make_response(redirect(url_for('admin.login')))
    response = make_header(response)
    return response

# Show all users
@admin.route('/Manage-User', methods=['GET'])
def users():
    if 'user' not in session:
        return redirect(url_for('admin.login'))

    try:
        connection = connect_db()
        cursor = connection.cursor(dictionary=True)

        # Fetch non-archived users
        cursor.execute("SELECT * FROM customers WHERE is_archived = FALSE")
        active_users = cursor.fetchall()

        # Fetch archived users
        cursor.execute("SELECT * FROM customers WHERE is_archived = TRUE")
        archived_users = cursor.fetchall()

        cursor.close()
        connection.close()

        message = session.pop('message', None)
        return render_template("users.html", active_users=active_users, archived_users=archived_users, message=message)
    except Exception as e:
        return render_template("users.html", active_users=[], archived_users=[], message=f"Error fetching users: {str(e)}")



# Archive user (set inactive)
@admin.route('/archive-user/<int:user_id>', methods=['POST'])
def archive_user(user_id):
    try:
        connection = connect_db()
        cursor = connection.cursor()
        cursor.execute("UPDATE customers SET is_archived = TRUE, status = 'Inactive' WHERE customer_id = %s", (user_id,))
        connection.commit()
        cursor.close()
        connection.close()
        session['message'] = "User archived successfully."
    except Exception as e:
        session['message'] = f"Error archiving user: {str(e)}"
    return redirect(url_for('admin.users'))


# Unarchive user (set active)
@admin.route('/unarchive-user/<int:user_id>', methods=['POST'])
def unarchive_user(user_id):
    try:
        connection = connect_db()
        cursor = connection.cursor()
        cursor.execute("UPDATE customers SET is_archived = FALSE, status = 'Active' WHERE customer_id = %s", (user_id,))
        connection.commit()
        cursor.close()
        connection.close()
        session['message'] = "User unarchived successfully."
    except Exception as e:
        session['message'] = f"Error unarchiving user: {str(e)}"
    return redirect(url_for('admin.users'))

@admin.route('/Manage-Categories', methods=['GET', 'POST'])
def categories():
    if 'user' not in session:
        return redirect(url_for('admin.login'))

    connection = connect_db()
    cursor = connection.cursor(dictionary=True)

    error_categories = None
    success_category = session.pop('success_category', None)

    if request.method == 'POST':
        category_name = request.form.get('category_name', '').strip()

        if not category_name:
            error_categories = "Category name cannot be empty."
        elif not category_name.isalpha():
            error_categories = "Category must include only letters, no numbers or symbols."
        elif len(category_name) < 4:
            error_categories = "Category must be at least 4 letters."
        else:
            cursor.execute("SELECT COUNT(*) FROM categories WHERE LOWER(category_name) = LOWER(%s)", (category_name,))
            (count,) = cursor.fetchone().values()
            if count > 0:
                error_categories = "Category already exists."
            else:
                try:
                    cursor.execute("INSERT INTO categories (category_name) VALUES (%s)", (category_name,))
                    connection.commit()
                    session['success_category'] = "Category added successfully!"
                    return redirect(url_for('admin.category'))
                except mysql.connector.Error as err:
                    error_categories = f"Error: {err}"

    # Separate categories by archive status
    cursor.execute("SELECT category_id, category_name, is_archived FROM categories")
    all_categories = cursor.fetchall()

    active_categories = [cat for cat in all_categories if not cat['is_archived']]
    archived_categories = [cat for cat in all_categories if cat['is_archived']]

    cursor.close()
    connection.close()

    return render_template("category.html", active_categories=active_categories, archived_categories=archived_categories, error_categories=error_categories, success_category=success_category)

@admin.route('/edit-category', methods=['POST'])
def edit_category():
    if 'user' not in session:
        return redirect(url_for('admin.login'))

    category_id = request.form.get('category_id')
    new_name = request.form.get('category_name', '').strip()

    # Validate category ID and new category name
    if not category_id:
        session['error_categories'] = "Category ID is missing."
        return redirect(url_for('admin.category'))

    if not new_name:
        session['error_categories'] = "Category name cannot be empty."
        return redirect(url_for('admin.categories'))

    if len(new_name) < 3 or len(new_name) > 50:
        session['error_categories'] = "Category name must be between 3 and 50 characters."
        return redirect(url_for('admin.categories'))

    try:
        connection = connect_db()
        cursor = connection.cursor()
        cursor.execute("UPDATE categories SET category_name = %s WHERE category_id = %s", (new_name, category_id))
        connection.commit()
        session['message'] = "Category updated successfully!"
    except mysql.connector.Error as err:
        session['error_categories'] = f"Error updating category: {err}"
    finally:
        cursor.close()
        connection.close()

    return redirect(url_for('admin.categories'))

@admin.route('/archive-category/<int:category_id>', methods=['POST'])
def archive_category(category_id):
    connection = connect_db()
    cursor = connection.cursor()
    cursor.execute("UPDATE categories SET is_archived = TRUE WHERE category_id = %s", (category_id,))
    connection.commit()
    cursor.close()
    connection.close()
    session['message'] = "Category archived successfully."
    return redirect(url_for('admin.categories'))

@admin.route('/unarchive-category/<int:category_id>', methods=['POST'])
def unarchive_category(category_id):
    connection = connect_db()
    cursor = connection.cursor()
    cursor.execute("UPDATE categories SET is_archived = FALSE WHERE category_id = %s", (category_id,))
    connection.commit()
    cursor.close()
    connection.close()
    session['message'] = "Category unarchived successfully."
    return redirect(url_for('admin.categories'))

@admin.route('/Manage-Item', methods=['GET', 'POST'])
def manageitem():
    if 'user' not in session:
        return redirect(url_for('admin.login'))

    error_item = None
    error_price = None
    error_image = None

    try:
        connection = connect_db()
        cursor = connection.cursor()

        # Fetch categories
        cursor.execute("SELECT category_id, category_name FROM categories")
        categories = cursor.fetchall()

        if request.method == "POST":
            name = request.form.get('name', '').strip()
            price_input = request.form.get('price', '').strip()
            category_id = request.form.get('category_id', '').strip()
            image = request.files.get('image')

            valid = True

            # Validate name
            if not name:
                error_item = "Item name is required."
                valid = False
            elif not all(word.isalpha() for word in name.split()):
                error_item = "Item name must contain only letters and spaces. No numbers or symbols."
                valid = False
            elif len(name) < 4 or len(name) > 19:
                error_item = "Item name must be between 4 and 19 characters long."
                valid = False
            else:
                # Check for duplicate item name (case-insensitive)
                cursor.execute("SELECT COUNT(*) FROM items WHERE LOWER(item_name) = LOWER(%s)", (name,))
                (count,) = cursor.fetchone()
                if count > 0:
                    error_item = "Item name already exists."
                    valid = False

            # Validate price
            try:
                price = float(price_input)
                if price < 0:
                    error_price = "Price cannot be negative."
                    valid = False
            except ValueError:
                error_price = "Invalid price format."
                valid = False

            # Validate image
            if not image or image.filename == '':
                error_image = "Image is required."
                valid = False
            elif not allowed_file(image.filename):
                error_image = "Invalid file format. Only images (JPG, JPEG, PNG, GIF) are allowed."
                valid = False

            # If all is valid, insert into DB and redirect
            if valid:
                image_data = image.read()
                try:
                    cursor.execute(
                        "INSERT INTO items (item_name, price, image, category_id) VALUES (%s, %s, %s, %s)",
                        (name, price, image_data, category_id)
                    )
                    connection.commit()
                    flash("Item added successfully!", "success")
                    return redirect(url_for('admin.manageitem'))  # PRG fix
                except Exception as e:
                    error_item = f"Database error: {str(e)}"

        # Always fetch items for display
        cursor.execute("""
            SELECT items.item_id, items.item_name, items.price, items.image, items.category_id, categories.category_name
            FROM items
            LEFT JOIN categories ON items.category_id = categories.category_id
        """)
        items = cursor.fetchall()

        processed_items = []
        for item in items:
            item_id, item_name, price, image_data, category_id, category_name = item
            image_base64 = base64.b64encode(image_data).decode('utf-8') if image_data else None
            processed_items.append((item_id, item_name, price, image_base64, category_id, category_name or "Uncategorized"))

        cursor.close()
        connection.close()

    except Exception as e:
        error_item = f"Unexpected error: {str(e)}"
        processed_items = []
        categories = []

    return render_template(
        "mitems.html",
        items=processed_items,
        categories=categories,
        error_item=error_item,
        error_price=error_price,
        error_image=error_image
    )

@admin.route('/delete/<int:item_id>', methods=['GET'])
def delete_item(item_id):
    try:
        connection = connect_db()
        cursor = connection.cursor()
        
        # Ensure the item exists before attempting to delete it
        cursor.execute("SELECT item_id FROM items WHERE item_id = %s", (item_id,))
        item = cursor.fetchone()

        if not item:
            flash("Item not found.", "danger")
            return redirect(url_for('admin.manageitem'))

        cursor.execute("DELETE FROM items WHERE item_id = %s", (item_id,))
        connection.commit()
        cursor.close()
        connection.close()
        flash("Item deleted successfully!", "success")
        return redirect(url_for('admin.manageitem'))
    except Exception as e:
        return f"Error deleting item: {str(e)}", 500

@admin.route('/edit-item/<int:item_id>', methods=['POST'])
def edit_item(item_id):
    # Fetch the current item details from the database
    try:
        connection = connect_db()
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM items WHERE item_id = %s", (item_id,))
        item = cursor.fetchone()

        if not item:
            flash("Item not found.", "danger")
            return redirect(url_for('admin.manageitem'))

        item_name, price, image_data, category_id = item[1], item[2], item[3], item[4]

        cursor.execute("SELECT category_id, category_name FROM categories")
        categories = cursor.fetchall()

    except Exception as e:
        flash(f"Error fetching item details: {str(e)}", "danger")
        return redirect(url_for('admin.manageitem'))

    error_edit_item = None
    error_edit_price = None
    error_edit_image = None

    # Process the form submission (POST request)
    name = request.form.get('name', '').strip()
    price_input = request.form.get('price', '').strip()
    category_id = request.form.get('category_id', '').strip()
    image = request.files.get('image')

    valid = True

    # Validate Item Name
    if not name:
        error_edit_item = "Item name is required."
        valid = False
    elif not all(word.isalpha() for word in name.split()):
        error_edit_item = "Item name must contain only letters and spaces. No numbers or symbols."
        valid = False
    elif len(name) < 4 or len(name) > 19:
        error_edit_item = "Item name must be between 4 and 19 characters long."
        valid = False

    # Validate Price
    try:
        price = float(price_input)
        if price < 0:
            error_edit_price = "Price cannot be negative."
            valid = False
    except ValueError:
        error_edit_price = "Invalid price format."
        valid = False

    # Validate Image (optional for edit)
    if image and image.filename != '':
        if not allowed_file(image.filename):
            error_edit_image = "Invalid file format. Only images (JPG, JPEG, PNG, GIF) are allowed."
            valid = False
        if valid:  # Only proceed with image if everything else is valid
            image_data = image.read()

    # If validation failed, return to form with errors
    if not valid:
        flash(error_edit_item or error_edit_price or error_edit_image, "danger")
        return redirect(url_for('admin.manageitem'))

    # If everything is valid, update the item in the database
    try:
        if image and image.filename != '':  # Update if new image provided
            cursor.execute(
                "UPDATE items SET item_name=%s, price=%s, image=%s, category_id=%s WHERE item_id=%s",
                (name, price, image_data, category_id, item_id)
            )
        else:  # No new image, update only name, price, and category
            cursor.execute(
                "UPDATE items SET item_name=%s, price=%s, category_id=%s WHERE item_id=%s",
                (name, price, category_id, item_id)
            )

        connection.commit()
        flash("Item updated successfully!", "success")

    except Exception as e:
        flash(f"Error updating item: {str(e)}", "danger")

    finally:
        cursor.close()
        connection.close()

    return redirect(url_for('admin.manageitem'))  # Redirect to the same page after update

@admin.route('/Manage-Orders', methods=['GET'])
def morders():
        return render_template("morders.html")
    
@admin.route('/api/morders', methods=['GET'])
def manage_orders():
    if 'user' not in session:
        return jsonify({'error': 'User not logged in'}), 401

    db = connect_db()
    cursor = db.cursor()

    try:
        # Get all orders with customer info
        cursor.execute("""
            SELECT o.order_id, o.ordered_at, o.total_amount, o.status, o.payment_ss, o.cancellation_reason,
                   c.full_name, c.customer_id
            FROM orders o
            JOIN customers c ON o.customer_id = c.customer_id
            ORDER BY o.ordered_at DESC
        """)

        order_rows = cursor.fetchall()

        customers_dict = {}
        orders_grouped = {}

        for row in order_rows:
            (order_id, ordered_at, total_amount, status, payment_ss, cancel_reason,
             full_name, customer_id) = row

            if customer_id not in customers_dict:
                customers_dict[customer_id] = {
                    'customer_id': customer_id,
                    'full_name': full_name,
                    'email': '',     # You can fill this in if needed
                    'contact': '',
                    'address': ''
                }
                orders_grouped[customer_id] = []

            # Get items for this order
            cursor.execute("""
                SELECT i.item_name, i.price, i.image, oi.quantity
                FROM order_items oi
                JOIN items i ON oi.item_id = i.item_id
                WHERE oi.order_id = %s
            """, (order_id,))
            item_rows = cursor.fetchall()

            items = [{
                'name': item_name,
                'price': float(price),
                'image': base64.b64encode(image).decode('utf-8') if image else None,
                'quantity': quantity
            } for item_name, price, image, quantity in item_rows]

            orders_grouped[customer_id].append({
                'order_id': order_id,
                'ordered_at': ordered_at.strftime('%Y-%m-%d %H:%M'),
                'total_amount': float(total_amount),
                'status': status,
                'payment_ss': base64.b64encode(payment_ss).decode('utf-8') if payment_ss else None,
                'cancellation_reason': cancel_reason,
                'items': items
            })

        customers = []
        for cust_id, cust_data in customers_dict.items():
            customers.append({
                'customer': cust_data,
                'orders': orders_grouped[cust_id]
            })

        return jsonify({
            'customers': customers
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

    finally:
        cursor.close()
        db.close()

@admin.route('/api/processing_order', methods=['POST'])
def processing_order():
    if 'user' not in session:
        return jsonify({'error': 'User not logged in'}), 401

    db = connect_db()
    cursor = db.cursor()

    try:
        order_id = request.json.get('order_id')

        if not order_id:
            return jsonify({'error': 'Order ID is required'}), 400

        # Update the order status to 'Accepted'
        cursor.execute("""
            UPDATE orders
            SET status = 'Processing'
            WHERE order_id = %s
        """, (order_id,))

        db.commit()

        return jsonify({'message': 'Order Processing'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

    finally:
        cursor.close()
        db.close()



@admin.route('/api/accept_order', methods=['POST'])
def accept_order():
    if 'user' not in session:
        return jsonify({'error': 'User not logged in'}), 401

    db = connect_db()
    cursor = db.cursor()

    try:
        order_id = request.json.get('order_id')

        if not order_id:
            return jsonify({'error': 'Order ID is required'}), 400

        # Update the order status to 'Accepted'
        cursor.execute("""
            UPDATE orders
            SET status = 'Completed'
            WHERE order_id = %s
        """, (order_id,))

        db.commit()

        return jsonify({'message': 'Order accepted successfully'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

    finally:
        cursor.close()
        db.close()
        
        
@admin.route('/api/cancel_order', methods=['POST'])
def cancel_order():
    if 'user' not in session:
        return jsonify({'error': 'User not logged in'}), 401

    db = connect_db()
    cursor = db.cursor()

    try:
        # Get the order ID from the request body
        order_id = request.json.get('order_id')

        if not order_id:
            return jsonify({'error': 'Order ID is required'}), 400

        # Update the order status to 'Cancelled'
        cursor.execute("""
            UPDATE orders
            SET status = 'Cancelled'
            WHERE order_id = %s
        """, (order_id,))

        # Commit the transaction
        db.commit()

        # Check if the update was successful
        if cursor.rowcount == 0:
            return jsonify({'error': 'Order not found or already cancelled'}), 404

        return jsonify({'message': 'Order cancelled successfully'})

    except Exception as e:
        print(f"Error canceling order: {str(e)}")
        return jsonify({'error': 'An error occurred while canceling the order'}), 500

    finally:
        cursor.close()
        db.close()