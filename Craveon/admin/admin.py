import base64
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify, make_response
import mysql.connector
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
import datetime
import requests

admin = Blueprint('admin', __name__, template_folder="template")
bcrypt = Bcrypt()

# Support multiple database configurations (local and remote)
DB_CONFIGS = {
    'local': {
        'host': '192.168.1.68',
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

def get_db_config():
    # Choose config based on environment variable, session, or other logic
    # Example: use ?db=flask_connection in query string to select remote DB
    db_key = request.args.get('db', 'local')
    return DB_CONFIGS.get(db_key, DB_CONFIGS['local'])

def connect_db():
    return mysql.connector.connect(**get_db_config())

ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def make_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, proxy-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@admin.app_template_filter('b64encode')
def b64encode_filter(data):
    return base64.b64encode(data).decode('utf-8') if data else ''

@admin.route('/')
def index():
    if 'admin' not in session:
        return redirect(url_for('admin.login'))

    db = connect_db()
    cursor = db.cursor()

    # Total customers
    cursor.execute("SELECT COUNT(*) FROM users")
    total_customers = cursor.fetchone()[0]

    # Total sales (completed only)
    cursor.execute("SELECT SUM(total_amount) FROM orders WHERE status = 'Completed'")
    result = cursor.fetchone()[0]
    total_sales = result if result else 0

    # Top-selling items this month: quantity & total revenue
    cursor.execute("""
        SELECT 
            i.item_name, 
            SUM(oi.quantity) AS total_quantity, 
            SUM(oi.quantity * i.price) AS total_revenue
        FROM order_items oi
        JOIN items i ON oi.item_id = i.item_id
        JOIN orders o ON oi.order_id = o.order_id
        WHERE MONTH(o.ordered_at) = MONTH(CURRENT_DATE())
          AND YEAR(o.ordered_at) = YEAR(CURRENT_DATE())
          AND o.status = 'Completed'
        GROUP BY i.item_name
        ORDER BY total_quantity DESC
        LIMIT 10
    """)
    popular_items = cursor.fetchall()

    item_names = [item[0] for item in popular_items]
    item_quantities = [item[1] for item in popular_items]
    item_revenues = [float(item[2]) for item in popular_items]  # Ensure float for JSON

    return render_template('index.html',
                           total_customers=total_customers,
                           total_sales=total_sales,
                           item_names=item_names,
                           item_sales=item_quantities,
                           item_revenues=item_revenues)


@admin.route('/login', methods=['GET', 'POST'])
def login():
    if 'admin' in session:
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
            session['admin'] = email
            return redirect(url_for('admin.index'))
        else:
            msg = emailmsg or passwordmsg

    response = make_response(render_template('login.html', msg=msg, emailmsg=emailmsg, passwordmsg=passwordmsg))
    return make_header(response)

@admin.route('/logout')
def logout():
    session.pop('admin', None)
    response = make_response(redirect(url_for('admin.login')))
    response = make_header(response)
    return response

@admin.route('/Manage-User', methods=['GET'])
def users():
    return render_template("users.html")

@admin.route('/api/manage-users', methods=['GET'])
def api_manage_users():
    if 'admin' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    connection = None   
    cursor = None
    try:
        connection = connect_db()
        cursor = connection.cursor(dictionary=True)

        # Fetch active users
        cursor.execute("SELECT * FROM users WHERE is_archived = FALSE")
        active_users = cursor.fetchall()

        # Fetch archived users
        cursor.execute("SELECT * FROM users WHERE is_archived = TRUE")
        archived_users = cursor.fetchall()

        # Safely process user images
        for user in active_users + archived_users:
            user_img = user.get("user_img")
            if user_img and isinstance(user_img, (bytes, bytearray)):
                user["user_img"] = base64.b64encode(user_img).decode('utf-8')
            elif isinstance(user_img, str):
                user["user_img"] = user_img  # Already base64-encoded
            else:
                user["user_img"] = None

        # Fetch completed transactions
        cursor.execute("""
            SELECT 
                o.order_id,
                o.user_id,
                o.total_amount,
                o.status,
                o.ordered_at
            FROM orders o
            WHERE o.status = 'Completed'
            ORDER BY o.ordered_at DESC
        """)
        all_transactions = cursor.fetchall()

        # Fetch items in those orders
        cursor.execute("""
            SELECT 
                oi.order_id,
                i.item_name,
                oi.quantity
            FROM order_items oi
            JOIN items i ON oi.item_id = i.item_id
        """)
        order_items = cursor.fetchall()

        # Group items by order ID
        items_by_order = {}
        for item in order_items:
            oid = item["order_id"]
            items_by_order.setdefault(oid, []).append({
                "item_name": item["item_name"],
                "quantity": item["quantity"]
            })

        # Group transactions by user ID
        transactions_by_user = {}
        for txn in all_transactions:
            txn["items"] = items_by_order.get(txn["order_id"], [])
            uid = txn["user_id"]
            transactions_by_user.setdefault(uid, []).append(txn)

        return jsonify({
            "active_users": active_users,
            "archived_users": archived_users,
            "transactions_by_user": transactions_by_user
        })

    except Exception as e:
        print("Error fetching users:", e)
        return jsonify({"error": f"Error fetching users: {str(e)}"}), 500

    finally:
        if cursor: cursor.close()
        if connection: connection.close()
@admin.route('/archive-user/<int:user_id>', methods=['POST'])
def archive_user(user_id):
    try:
        connection = connect_db()
        cursor = connection.cursor()
        cursor.execute("""
            UPDATE users
            SET is_archived = TRUE
            WHERE user_id = %s
        """, (user_id,))
        connection.commit()
        cursor.close()
        connection.close()
        return jsonify({'message': 'User archived successfully'}), 200
    except Exception as e:
        print("Error archiving user:", str(e))
        return jsonify({'error': f"Error archiving user: {str(e)}"}), 500

@admin.route('/unarchive-user/<int:user_id>', methods=['POST'])
def unarchive_user(user_id):
    try:
        connection = connect_db()
        cursor = connection.cursor()
        cursor.execute("""
            UPDATE users
            SET is_archived = FALSE
            WHERE user_id = %s
        """, (user_id,))
        connection.commit()
        cursor.close()
        connection.close()
        return jsonify({'message': 'User unarchived successfully'}), 200
    except Exception as e:
        print("Error unarchiving user:", str(e))
        return jsonify({'error': f"Error unarchiving user: {str(e)}"}), 500


@admin.route('/Manage-Categories', methods=['GET', 'POST'])
def categories():
    if 'admin' not in session:
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
                    return redirect(url_for('admin.categories'))
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
    if 'admin' not in session:
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

@admin.route('/api/Manage-Item', methods=['GET'])
def manage_items():
    try:
        connection = connect_db()
        cursor = connection.cursor(dictionary=True)

        # Fetch active items
        cursor.execute("""
            SELECT items.item_id, items.item_name, items.price, items.image, items.category_id, categories.category_name
            FROM items
            LEFT JOIN categories ON items.category_id = categories.category_id
            WHERE items.is_archived = FALSE
        """)
        active_items = cursor.fetchall()

        # Fetch archived items
        cursor.execute("""
            SELECT items.item_id, items.item_name, items.price, items.image, items.category_id, categories.category_name
            FROM items
            LEFT JOIN categories ON items.category_id = categories.category_id
            WHERE items.is_archived = TRUE
        """)
        archived_items = cursor.fetchall()

        def process_items(raw_items):
            result = []
            for item in raw_items:
                item_id, item_name, price, image_data, category_id, category_name = item.values()
                image_base64 = base64.b64encode(image_data).decode('utf-8') if image_data else None
                result.append({
                    'item_id': item_id,
                    'item_name': item_name,
                    'price': float(price),
                    'image': image_base64,
                    'category_id': category_id,
                    'category_name': category_name or "Uncategorized"
                })
            return result
        return jsonify({
            'data': {
                'active_items': process_items(active_items),
                'archived_items': process_items(archived_items)
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@admin.route('/api/Manage-Item', methods=['GET'])
def api_manage_item():
    try:
        connection = connect_db()
        cursor = connection.cursor(dictionary=True)

        # Fetch active items
        cursor.execute("""
            SELECT items.item_id, items.item_name, items.price, items.image, items.category_id, categories.category_name
            FROM items
            LEFT JOIN categories ON items.category_id = categories.category_id
            WHERE items.is_archived = FALSE
        """)
        active_items = cursor.fetchall()

        # Fetch archived items
        cursor.execute("""
            SELECT items.item_id, items.item_name, items.price, items.image, items.category_id, categories.category_name
            FROM items
            LEFT JOIN categories ON items.category_id = categories.category_id
            WHERE items.is_archived = TRUE
        """)
        archived_items = cursor.fetchall()

        def process_items(raw_items):
            result = []
            for item in raw_items:
                item_id, item_name, price, image_data, category_id, category_name = item.values()
                image_base64 = base64.b64encode(image_data).decode('utf-8') if image_data else None
                result.append({
                    'item_id': item_id,
                    'item_name': item_name,
                    'price': float(price),
                    'image': image_base64,
                    'category_id': category_id,
                    'category_name': category_name or "Uncategorized"
                })
            return result
        return jsonify({
            'data': {
                'active_items': process_items(active_items),
                'archived_items': process_items(archived_items)
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@admin.route('/Manage-Item', methods=['GET', 'POST'])
def manageitem():
    if request.headers.get('Accept') == 'application/json':
        try:
            connection = connect_db()
            cursor = connection.cursor()
            cursor.execute("""
                SELECT items.item_id, items.item_name, items.price, items.image, items.category_id, categories.category_name
                FROM items
                LEFT JOIN categories ON items.category_id = categories.category_id
                WHERE items.is_archived = 0
            """)
            active_items = cursor.fetchall()
            cursor.execute("""
                SELECT items.item_id, items.item_name, items.price, items.image, items.category_id, categories.category_name
                FROM items
                LEFT JOIN categories ON items.category_id = categories.category_id
                WHERE items.is_archived = 1
            """)
            archived_items = cursor.fetchall()
            cursor.close()
            connection.close()

            def process_items(raw_items):
                result = []
                for item in raw_items:
                    item_id, item_name, price, image_data, category_id, category_name = item
                    image_base64 = base64.b64encode(image_data).decode('utf-8') if image_data else None
                    result.append({
                        'item_id': item_id,
                        'item_name': item_name,
                        'price': float(price),
                        'image': image_base64,
                        'category_id': category_id,
                        'category_name': category_name or "Uncategorized"
                    })
                return result

            return jsonify({
                'active_items': process_items(active_items),
                'archived_items': process_items(archived_items)
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    if 'admin' not in session:
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
                error_item = "Item name must contain only letters and spaces."
                valid = False
            elif len(name) < 4 or len(name) > 19:
                error_item = "Item name must be between 4 and 19 characters."
                valid = False
            else:
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
                error_image = "Invalid image format. Only JPG, JPEG, PNG, GIF allowed."
                valid = False

            if valid:
                image_data = image.read()
                try:
                    cursor.execute("""
                        INSERT INTO items (item_name, price, image, category_id, is_archived)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (name, price, image_data, category_id, 0))
                    connection.commit()
                    flash("Item added successfully!", "success")
                    return redirect(url_for('admin.manageitem'))
                except Exception as e:
                    error_item = f"Database error: {str(e)}"

        # Get active items
        cursor.execute("""
            SELECT items.item_id, items.item_name, items.price, items.image, items.category_id, categories.category_name
            FROM items
            LEFT JOIN categories ON items.category_id = categories.category_id
            WHERE items.is_archived = 0
        """)
        active_items = cursor.fetchall()

        # Get archived items
        cursor.execute("""
            SELECT items.item_id, items.item_name, items.price, items.image, items.category_id, categories.category_name
            FROM items
            LEFT JOIN categories ON items.category_id = categories.category_id
            WHERE items.is_archived = 1
        """)
        archived_items = cursor.fetchall()

        # Process both
        def process_items(raw_items):
            result = []
            for item in raw_items:
                item_id, item_name, price, image_data, category_id, category_name = item
                image_base64 = base64.b64encode(image_data).decode('utf-8') if image_data else None
                result.append((item_id, item_name, price, image_base64, category_id, category_name or "Uncategorized"))
            return result

        processed_active = process_items(active_items)
        processed_archived = process_items(archived_items)

        cursor.close()
        connection.close()

    except Exception as e:
        error_item = f"Unexpected error: {str(e)}"
        processed_active = []
        processed_archived = []
        categories = []

    return render_template(
        "mitems.html",
        items=processed_active,
        archived_items=processed_archived,
        categories=categories,
        error_item=error_item,
        error_price=error_price,
        error_image=error_image
    )


@admin.route('/archive-item/<int:item_id>')
def archive_item(item_id):
    if 'admin' not in session:
        return redirect(url_for('admin.login'))

    connection = connect_db()
    cursor = connection.cursor()
    try:
        cursor.execute("UPDATE items SET is_archived = TRUE WHERE item_id = %s", (item_id,))
        connection.commit()
        flash("Item archived successfully.", "success")
    except Exception as e:
        flash(f"Error archiving item: {str(e)}", "danger")
    finally:
        cursor.close()
        connection.close()

    return redirect(url_for('admin.manageitem'))


@admin.route('/restore-item/<int:item_id>')
def restore_item(item_id):
    if 'admin' not in session:
        return redirect(url_for('admin.login'))

    try:
        connection = connect_db()
        cursor = connection.cursor()
        cursor.execute("UPDATE items SET is_archived = 0 WHERE item_id = %s", (item_id,))
        connection.commit()
        flash("Item has been successfully restored.", "success")
    except Exception as e:
        print("Error restoring item:", e)
        flash("Failed to restore item.", "danger")
    finally:
        cursor.close()
        connection.close()

    return redirect(url_for('admin.manageitem'))



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

@admin.route('/morders', methods=['GET'])
def manage_orders():
    if 'admin' not in session:
        return jsonify({'error': 'Admin not logged in'}), 401

    db = connect_db()
    cursor = db.cursor(dictionary=True)

    try:
        # Only fetch orders with payment screenshot submitted
        cursor.execute("""
            SELECT o.order_id, o.ordered_at, o.total_amount, o.status, o.payment_ss, o.cancellation_reason,
                   u.user_id, u.first_name, u.middle_name, u.last_name, u.email, u.contact, u.address
            FROM orders o
            JOIN users u ON o.user_id = u.user_id
            WHERE o.payment_ss IS NOT NULL
            ORDER BY o.ordered_at DESC
        """)
        order_rows = cursor.fetchall()

        users_dict = {}
        orders_grouped = {}

        for row in order_rows:
            user_id = row['user_id']
            full_name = f"{row['first_name']} {row['middle_name'] + ' ' if row['middle_name'] else ''}{row['last_name']}".strip()

            if user_id not in users_dict:
                users_dict[user_id] = {
                    'customer_id': user_id,
                    'full_name': full_name,
                    'email': row['email'],
                    'contact': row['contact'],
                    'address': row['address']
                }
                orders_grouped[user_id] = []

            # Fetch order items
            cursor.execute("""
                SELECT i.item_name, i.price, i.image, oi.quantity
                FROM order_items oi
                JOIN items i ON oi.item_id = i.item_id
                WHERE oi.order_id = %s
            """, (row['order_id'],))
            item_rows = cursor.fetchall()

            items = [{
                'name': item['item_name'],
                'price': float(item['price']),
                'image': base64.b64encode(item['image']).decode('utf-8') if item['image'] else None,
                'quantity': item['quantity']
            } for item in item_rows]

            orders_grouped[user_id].append({
                'order_id': row['order_id'],
                'ordered_at': row['ordered_at'].strftime('%Y-%m-%d %H:%M'),
                'total_amount': float(row['total_amount']),
                'status': row['status'],
                'payment_ss': row['payment_ss'],
                'payment_submitted': True,
                'cancellation_reason': row['cancellation_reason'],
                'items': items
            })

        customers = []
        for uid, user_data in users_dict.items():
            customers.append({
                'customer': user_data,
                'orders': orders_grouped[uid]
            })

        return jsonify({'customers': customers})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

    finally:
        cursor.close()
        db.close()


        
@admin.route('/api/processing_order', methods=['POST'])
def processing_order():
    if 'admin' not in session:
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
    if 'admin' not in session:
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
    if 'admin' not in session:
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



@admin.route('/test-hotel-users', methods=['GET'])
def test_hotel_users():
    db = mysql.connector.connect(**DB_CONFIGS['flask_connection'])
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM bookings WHERE status = %s", ('checked_in',))
        users = cursor.fetchall()
        for user in users:
            for k, v in user.items():
                if isinstance(v, datetime.timedelta):
                    user[k] = str(v)
                # Handle image fields for both JSON and HTML
                if 'img' in k.lower() or 'photo' in k.lower() or 'avatar' in k.lower() or 'image' in k.lower():
                    if v:
                        if isinstance(v, (bytes, bytearray)):
                            user[k] = 'data:image/jpeg;base64,' + base64.b64encode(v).decode('utf-8')
                        elif isinstance(v, str) and (v.startswith('http://') or v.startswith('https://')):
                            user[k] = v
                        elif isinstance(v, str):
                            # Assume Cloudinary public ID or versioned path
                            if v.startswith('v') and '/' in v:
                                user[k] = f"https://res.cloudinary.com/ddjp3phzz/image/upload/{v}"
                            else:
                                user[k] = f"https://res.cloudinary.com/ddjp3phzz/image/upload/{v}.jpg"
                    else:
                        user[k] = None
        # If HTML requested, render template
        if request.args.get('format') == 'html' or 'text/html' in request.headers.get('Accept', ''):
            return render_template('test.html', checked_in_users=users, error=None)
        # Otherwise, return JSON
        return jsonify({'checked_in_users': users})
    except Exception as e:
        if request.args.get('format') == 'html' or 'text/html' in request.headers.get('Accept', ''):
            return render_template('test.html', checked_in_users=[], error=str(e))
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        db.close()

@admin.route('/test-hotel-users-ui', methods=['GET'])
def test_hotel_users_ui():
    # Always render the template, let the template handle empty state
    return render_template('test.html', checked_in_users=None, error=None)

@admin.route('/sales')
def sales():
    return render_template('sales.html')

from collections import defaultdict
from decimal import Decimal

@admin.route('/api/sales', methods=['GET'])
def get_sales_data():
    year = request.args.get('year')
    month = request.args.get('month')
    item = request.args.get('item')
    category = request.args.get('category')

    conn = connect_db()
    cursor = conn.cursor(dictionary=True)

    query = """
        SELECT 
            o.ordered_at,
            oi.quantity,
            i.price,
            i.item_name,
            c.category_name
        FROM orders o
        JOIN order_items oi ON o.order_id = oi.order_id
        JOIN items i ON oi.item_id = i.item_id
        JOIN categories c ON i.category_id = c.category_id
        WHERE o.status = 'Completed'
    """

    values = []
    if year:
        query += " AND YEAR(o.ordered_at) = %s"
        values.append(year)
    if month:
        query += " AND MONTH(o.ordered_at) = %s"
        values.append(month)
    if item:
        query += " AND i.item_name = %s"
        values.append(item)
    if category:
        query += " AND c.category_name = %s"
        values.append(category)

    query += " ORDER BY o.ordered_at DESC"
    cursor.execute(query, tuple(values))
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    # Aggregate results
    from collections import defaultdict
    from decimal import Decimal

    sales_data = defaultdict(lambda: defaultdict(lambda: {"total": Decimal("0.00"), "category": ""}))
    month_names = {}

    for row in rows:
        ordered_at = row['ordered_at']
        item_name = row['item_name']
        quantity = row['quantity']
        price = row['price']
        category_name = row['category_name']
        total = quantity * price

        year_month = (ordered_at.year, ordered_at.month)
        sales_data[year_month][item_name]["total"] += total
        sales_data[year_month][item_name]["category"] = category_name
        month_names[ordered_at.month] = ordered_at.strftime('%B')

    result = []
    for (y, m), items in sorted(sales_data.items(), reverse=True):
        for item_name, data in items.items():
            result.append({
                'year': y,
                'month_number': m,
                'month': month_names[m],
                'item_name': item_name,
                'category_name': data["category"],
                'total': float(data["total"])
            })

    return jsonify({'sales': result})

@admin.route('/dashboard')
def admin_dashboard():
    # Sample data - replace with your actual data from database
    data = {
        'total_sales': 25680.00,
        'total_orders': 184,
        'total_customers': 1248,
        'avg_order_value': 139.57,
        'revenue_data': [1200, 1900, 1500, 2200, 1800, 2500, 3000],
        'revenue_dates': ['1', '5', '10', '15', '20', '25', '30'],
        'category_sales': [45, 25, 20, 10],
        'categories': ['Food', 'Beverages', 'Desserts', 'Snacks'],
        'top_items': ['Burger Deluxe', 'Pasta Carbonara', 'Chicken BBQ', 'Milkshake', 'Pizza Supreme', 'Caesar Salad', 'Cheesecake'],
        'top_quantities': [140, 120, 95, 85, 75, 65, 50],
        'top_revenues': [1400, 1200, 950, 850, 750, 650, 500],
        'recent_orders': [
            {'id': 'CR-7842', 'customer': 'John Smith', 'date': 'Jul 8, 2023', 'amount': '1,240.00', 'status': 'completed'},
            # ... other orders
        ]
    }
    return render_template('index.html', **data)