import base64
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify, make_response
import mysql.connector
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
import datetime
from collections import defaultdict
from decimal import Decimal

admin = Blueprint('admin', __name__, template_folder="template")
bcrypt = Bcrypt()

DB_CONFIGS = {
    'local': {
        'host': 'localhost',
        'database': 'craveon',
        'user': 'root',
        'password': 'ClodAndrei8225',
    },
    'flask_connection': {
        'host': '192.168.1.11',
        'database': 'hotel_management',
        'user': 'root',
        'password': 'admin',
    }
}

def get_db_config():
    db_key = request.args.get('db', 'local')
    return DB_CONFIGS.get(db_key, DB_CONFIGS['local'])

def connect_db():
    return mysql.connector.connect(**get_db_config())

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
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

    conn = connect_db()
    cursor = conn.cursor(dictionary=True)
    try:
        # Total customers
        cursor.execute("SELECT COUNT(*) AS cnt FROM users")
        total_customers = cursor.fetchone()['cnt']

        # Total profit (sales minus 20% commission on hotel_user orders)
        cursor.execute("""
            SELECT COALESCE(SUM(
                (i.price * oi.quantity)
              - CASE WHEN u.hotel_user = 1
                     THEN (i.price * oi.quantity * 0.2)
                     ELSE 0
                END
            ), 0) AS total_profit
            FROM orders o
            JOIN order_items oi ON o.order_id = oi.order_id
            JOIN items i        ON oi.item_id   = i.item_id
            JOIN users u        ON o.user_id     = u.user_id
            WHERE o.status = 'Completed'
        """)
        total_profit = float(cursor.fetchone()['total_profit'])

        # Top-selling items this month: quantity & total revenue
        cursor.execute("""
            SELECT 
                i.item_name, 
                SUM(oi.quantity)           AS total_quantity, 
                SUM(oi.quantity * i.price) AS total_revenue
            FROM order_items oi
            JOIN items i ON oi.item_id = i.item_id
            JOIN orders o ON oi.order_id = o.order_id
            WHERE o.status = 'Completed'
              AND MONTH(o.ordered_at) = MONTH(CURRENT_DATE())
              AND YEAR(o.ordered_at)  = YEAR(CURRENT_DATE())
            GROUP BY i.item_name
            ORDER BY total_quantity DESC
            LIMIT 7
        """)
        popular_items = cursor.fetchall()

        item_names    = [row['item_name']       for row in popular_items]
        item_sales    = [int(row['total_quantity'])  for row in popular_items]
        item_revenues = [float(row['total_revenue']) for row in popular_items]

        return render_template(
            'index.html',
            total_profit=total_profit,
            total_customers=total_customers,
            item_names=item_names,
            item_sales=item_sales,
            item_revenues=item_revenues
        )
    finally:
        cursor.close()
        conn.close()



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
    # JSON response handler
    if request.headers.get('Accept') == 'application/json':
        if 'admin' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
            
        try:
            connection = connect_db()
            cursor = connection.cursor()
            
            # Get both active and archived items
            cursor.execute("""
                SELECT i.item_id, i.item_name, i.price, i.image, 
                       i.category_id, c.category_name, i.is_archived
                FROM items i
                LEFT JOIN categories c ON i.category_id = c.category_id
                ORDER BY i.is_archived, i.item_name
            """)
            
            items = cursor.fetchall()
            
            def process_item(item):
                item_id, name, price, image, cat_id, cat_name, is_archived = item
                return {
                    'item_id': item_id,
                    'item_name': name,
                    'price': float(price),
                    'image': base64.b64encode(image).decode('utf-8') if image else None,
                    'category_id': cat_id,
                    'category_name': cat_name or "Uncategorized",
                    'is_archived': bool(is_archived)
                }

            active_items = [process_item(item) for item in items if not item[6]]
            archived_items = [process_item(item) for item in items if item[6]]
            
            return jsonify({
                'active_items': active_items,
                'archived_items': archived_items
            })
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
        finally:
            cursor.close()
            connection.close()

    # Normal HTML response handler
    if 'admin' not in session:
        return redirect(url_for('admin.login'))

    error_item = error_price = error_image = None
    categories = []
    active_items = []
    archived_items = []

    try:
        connection = connect_db()
        cursor = connection.cursor()

        # Handle form submission
        if request.method == "POST":
            name = request.form.get('name', '').strip()
            price = request.form.get('price', '').strip()
            category_id = request.form.get('category_id')
            image = request.files.get('image')

            # Validate inputs
            valid = True
            
            # Name validation
            if not name:
                error_item = "Item name is required."
                valid = False
            elif len(name) < 2 or len(name) > 50:
                error_item = "Item name must be between 2-50 characters."
                valid = False
                
            # Price validation
            try:
                price = float(price)
                if price <= 0:
                    error_price = "Price must be positive."
                    valid = False
            except ValueError:
                error_price = "Invalid price format."
                valid = False
                
            # Image validation
            if not image or image.filename == '':
                error_image = "Image is required."
                valid = False
            elif not allowed_file(image.filename):
                error_image = "Only JPG, JPEG, PNG, GIF allowed."
                valid = False

            if valid:
                image_data = image.read()
                try:
                    cursor.execute("""
                        INSERT INTO items (item_name, price, image, category_id, is_archived)
                        VALUES (%s, %s, %s, %s, 0)
                    """, (name, price, image_data, category_id))
                    connection.commit()
                    flash("Item added successfully!", "success")
                    return redirect(url_for('admin.manageitem'))
                except Exception as e:
                    connection.rollback()
                    error_item = f"Database error: {str(e)}"

        # Get categories
        cursor.execute("SELECT category_id, category_name FROM categories")
        categories = cursor.fetchall()

        # Get items
        cursor.execute("""
            SELECT i.item_id, i.item_name, i.price, i.image, 
                   i.category_id, c.category_name, i.is_archived
            FROM items i
            LEFT JOIN categories c ON i.category_id = c.category_id
            ORDER BY i.is_archived, i.item_name
        """)
        
        items = cursor.fetchall()
        
        # Process items
        def process_item(item):
            item_id, name, price, image, cat_id, cat_name, is_archived = item
            image_base64 = base64.b64encode(image).decode('utf-8') if image else None
            return (item_id, name, price, image_base64, cat_id, cat_name or "Uncategorized")

        active_items = [process_item(item) for item in items if not item[6]]
        archived_items = [process_item(item) for item in items if item[6]]

    except Exception as e:
        error_item = f"Database error: {str(e)}"
        if 'connection' in locals() and connection:
            connection.rollback()
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()
        if 'connection' in locals() and connection:
            connection.close()

    return render_template(
        "mitems.html",
        items=active_items,
        archived_items=archived_items,
        categories=categories,
        error_item=error_item,
        error_price=error_price,
        error_image=error_image
    )

@admin.route('/archive-item/<int:item_id>')
def archive_item(item_id):
    if 'admin' not in session:
        return redirect(url_for('admin.login'))

    try:
        connection = connect_db()
        cursor = connection.cursor()
        cursor.execute("UPDATE items SET is_archived = 1 WHERE item_id = %s", (item_id,))
        connection.commit()
        flash(f"Item ID {item_id} archived successfully.", "success")
    except Exception as e:
        flash(f"Error archiving item: {str(e)}", "danger")
        if connection:
            connection.rollback()
    finally:
        if cursor:
            cursor.close()
        if connection:
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
        flash(f"Item ID {item_id} restored successfully.", "success")
    except Exception as e:
        flash(f"Error restoring item: {str(e)}", "danger")
        if connection:
            connection.rollback()
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

    return redirect(url_for('admin.manageitem'))

@admin.route('/edit-item/<int:item_id>', methods=['POST'])
def edit_item(item_id):
    if 'admin' not in session:
        flash("You need to login first", "danger")
        return redirect(url_for('admin.login'))

    try:
        connection = connect_db()
        cursor = connection.cursor(dictionary=True)

        # Get form data
        name = request.form.get('name', '').strip()
        price = request.form.get('price', '').strip()
        category_id = request.form.get('category_id')
        image = request.files.get('image')

        # Validate inputs
        errors = []
        
        # Name validation
        if not name:
            errors.append("Item name is required.")
        elif len(name) < 2 or len(name) > 50:
            errors.append("Item name must be between 2-50 characters.")
            
        # Price validation
        try:
            price = float(price)
            if price <= 0:
                errors.append("Price must be positive.")
        except ValueError:
            errors.append("Invalid price format.")
            
        # Image validation (only if new image is provided)
        image_data = None
        if image and image.filename:
            if not allowed_file(image.filename):
                errors.append("Only JPG, JPEG, PNG, GIF allowed.")
            else:
                image_data = image.read()

        if errors:
            for error in errors:
                flash(error, "danger")
            return redirect(url_for('admin.manageitem'))

        # Build the update query based on provided fields
        update_fields = []
        params = []
        
        update_fields.append("item_name = %s")
        params.append(name)
        
        update_fields.append("price = %s")
        params.append(price)
        
        update_fields.append("category_id = %s")
        params.append(category_id)
        
        if image_data:
            update_fields.append("image = %s")
            params.append(image_data)
        
        params.append(item_id)  # For WHERE clause

        # Execute the update
        query = f"""
            UPDATE items 
            SET {', '.join(update_fields)}
            WHERE item_id = %s
        """
        cursor.execute(query, tuple(params))
        connection.commit()

        flash("Item updated successfully!", "success")
        return redirect(url_for('admin.manageitem'))

    except Exception as e:
        flash(f"Error updating item: {str(e)}", "danger")
        return redirect(url_for('admin.manageitem'))

    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()
        if 'connection' in locals() and connection:
            connection.close()

@admin.route('/Manage-Orders', methods=['GET'])
def morders():
    return render_template("morders.html")

@admin.route('/morders', methods=['GET'])
def manage_orders():
    db = connect_db()
    cursor = db.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT o.order_id, o.ordered_at, o.total_amount, o.status, o.payment_ss, o.cancellation_reason,
                   u.user_id, u.first_name, u.middle_name, u.last_name, u.email, u.contact, u.address, u.hotel_user
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
                    'address': row['address'],
                    'hotel_user': row['hotel_user'],
                }
                orders_grouped[user_id] = []

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
                'quantity': item['quantity']
            } for item in item_rows]

            orders_grouped[user_id].append({
                'order_id': row['order_id'],
                'ordered_at': row['ordered_at'].strftime('%Y-%m-%d %H:%M'),
                'total_amount': float(row['total_amount']),
                'status': row['status'],
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
        order_id = request.json.get('order_id')

        if not order_id:
            return jsonify({'error': 'Order ID is required'}), 400

        cursor.execute("""
            UPDATE orders
            SET status = 'Cancelled'
            WHERE order_id = %s
        """, (order_id,))

        db.commit()

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
                if 'img' in k.lower() or 'photo' in k.lower() or 'avatar' in k.lower() or 'image' in k.lower():
                    if v:
                        if isinstance(v, (bytes, bytearray)):
                            user[k] = 'data:image/jpeg;base64,' + base64.b64encode(v).decode('utf-8')
                        elif isinstance(v, str) and (v.startswith('http://') or v.startswith('https://')):
                            user[k] = v
                        elif isinstance(v, str):
                            if v.startswith('v') and '/' in v:
                                user[k] = f"https://res.cloudinary.com/ddjp3phzz/image/upload/{v}"
                            else:
                                user[k] = f"https://res.cloudinary.com/ddjp3phzz/image/upload/{v}.jpg"
                    else:
                        user[k] = None
        if request.args.get('format') == 'html' or 'text/html' in request.headers.get('Accept', ''):
            return render_template('test.html', checked_in_users=users, error=None)
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
    return render_template('test.html', checked_in_users=None, error=None)

@admin.route('/sales')
def sales():
    return render_template('sales.html')

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
            o.order_id,
            o.ordered_at,
            i.item_name,
            c.category_name,
            i.price,
            oi.quantity,
            u.hotel_user,  # Add this to identify Azurea users
            (i.price * oi.quantity) AS sales,
            CASE 
                WHEN u.hotel_user = 1 THEN (i.price * oi.quantity * 0.2)
                ELSE 0
            END AS commission,
            (i.price * oi.quantity) - 
            CASE 
                WHEN u.hotel_user = 1 THEN (i.price * oi.quantity * 0.2)
                ELSE 0
            END AS total
        FROM orders o
        JOIN order_items oi ON o.order_id = oi.order_id
        JOIN items i ON oi.item_id = i.item_id
        JOIN categories c ON i.category_id = c.category_id
        JOIN users u ON o.user_id = u.user_id
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

    for row in rows:
        row['hotel_user'] = bool(row['hotel_user'])
        row["year"] = row["ordered_at"].year
        row["month_number"] = row["ordered_at"].month
        row["month"] = row["ordered_at"].strftime('%B')
        
        row["price"] = float(row["price"])
        row["commission"] = float(row["commission"])
        row["total"] = float(row["total"])

    cursor.close()
    conn.close()
    return jsonify({'sales': rows})


@admin.route('/dashboard', methods=['GET'])
def admin_dashboard():
    if 'admin' not in session:
        return redirect(url_for('admin.login'))

    conn = connect_db()
    cursor = conn.cursor(dictionary=True)
    try:
        # Total customers
        cursor.execute("SELECT COUNT(*) AS cnt FROM users")
        total_customers = cursor.fetchone()['cnt']

        # Compute total profit exactly like /api/sales does:
        cursor.execute("""
            SELECT 
              COALESCE(SUM(
                (i.price * oi.quantity)
                - CASE WHEN u.hotel_user = 1 
                       THEN (i.price * oi.quantity * 0.2)
                       ELSE 0
                  END
              ), 0) AS total_profit
            FROM orders o
            JOIN order_items oi ON o.order_id = oi.order_id
            JOIN items i        ON oi.item_id   = i.item_id
            JOIN users u        ON o.user_id     = u.user_id
            WHERE o.status = 'Completed'
        """)
        total_profit = float(cursor.fetchone()['total_profit'])

        # Top 7 selling items this month (quantity & revenue)
        cursor.execute("""
            SELECT
              i.item_name,
              SUM(oi.quantity)            AS total_quantity,
              SUM(oi.quantity * i.price)  AS total_revenue
            FROM orders o
            JOIN order_items oi ON o.order_id = oi.order_id
            JOIN items i        ON oi.item_id   = i.item_id
            WHERE o.status = 'Completed'
              AND MONTH(o.ordered_at) = MONTH(CURRENT_DATE())
              AND YEAR(o.ordered_at)  = YEAR(CURRENT_DATE())
            GROUP BY i.item_name
            ORDER BY total_quantity DESC
            LIMIT 7
        """)
        rows = cursor.fetchall()
        item_names    = [r['item_name']       for r in rows]
        item_sales    = [int(r['total_quantity'])  for r in rows]
        item_revenues = [float(r['total_revenue']) for r in rows]

        return render_template(
            'index.html',
            total_profit=total_profit,
            total_customers=total_customers,
            item_names=item_names,
            item_sales=item_sales,
            item_revenues=item_revenues
        )
    finally:
        cursor.close()
        conn.close()


@admin.route('/reviews')
def reviews():
    if 'admin' not in session:
        return redirect(url_for('admin.login'))

    db = connect_db()
    cursor = db.cursor(dictionary=True)

    cursor.execute("""
        SELECT r.id, r.order_id, r.rating, r.comment, r.created_at,
        u.first_name, u.last_name
        FROM reviews r
        JOIN orders o ON r.order_id = o.order_id
        JOIN users u ON o.user_id = u.user_id
        ORDER BY r.created_at DESC
    """)
    reviews = cursor.fetchall()

    cursor.close()
    db.close()

    return render_template('reviews.html', reviews=reviews)
