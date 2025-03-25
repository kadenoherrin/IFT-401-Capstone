from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import random
from itsdangerous import URLSafeTimedSerializer
import os
from dotenv import load_dotenv
import threading
import time
from datetime import datetime, date
import pymysql
import time
import sqlalchemy.exc

load_dotenv()
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://{os.getenv('SQL_USERNAME')}:{os.getenv('SQL_PASSWORD')}@{os.getenv('MYSQL_HOST')}/{os.getenv('SQL_DATABASE')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

# Unauthorized handler: if not logged in, redirect to a custom unauthorized page
@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect(url_for('unauthorized'))

# -------------------- Models --------------------
class Users(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), default="user", nullable=False)
    balance = db.Column(db.Float, default=0.0)  


class Stock(db.Model):
    __tablename__ = 'stocks'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)  # Keep for descriptive purposes
    symbol = db.Column(db.String(10), unique=True, nullable=False)  # New column for stock symbol
    initial_price = db.Column(db.Float, nullable=False)
    live_price = db.Column(db.Float, nullable=False)  # New column for live price

class Transaction(db.Model):
    __tablename__ = 'transactions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    stock_id = db.Column(db.Integer, db.ForeignKey('stocks.id'), nullable=False)
    shares = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    transaction_type = db.Column(db.Enum('buy', 'sell'), nullable=False)
    transaction_date = db.Column(db.DateTime, server_default=db.func.current_timestamp())

class Admin(db.Model):
    __tablename__ = 'admin'
    id = db.Column(db.Integer, primary_key=True)
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)
    day_start = db.Column(db.String(10), nullable=False, default='Monday')
    day_end = db.Column(db.String(10), nullable=False, default='Friday')
    fluctuation = db.Column(db.Float, nullable=False, default=0.0)  # New column for fluctuation percentage

with app.app_context():
    connected = False
    retries = 10
    while not connected and retries > 0:
        try:
            db.create_all()
            connected = True
        except sqlalchemy.exc.OperationalError as e:
            print("Database not ready, retrying in 2 seconds...")
            time.sleep(2)
            retries -= 1

    if not connected:
        raise Exception("Could not connect to the database after several retries.")

    if not Admin.query.first():
        db.session.add(Admin(start_time="09:00:00", end_time="16:00:00", 
                             day_start="Monday", day_end="Friday", fluctuation=0.0))
        db.session.commit()
    for stock in Stock.query.all():
        if stock.live_price is None:
            stock.live_price = stock.initial_price
    db.session.commit()


# Function to fluctuate stock prices
def fluctuate_stock_prices():
    while True:
        with app.app_context():
            fluctuation = Admin.query.first().fluctuation if Admin.query.first() else 0.0
            stocks = Stock.query.all()
            for stock in stocks:
                change_percent = random.uniform(-fluctuation, fluctuation) / 100
                stock.live_price = max(0.01, stock.initial_price * (1 + change_percent))  # Calculate live price based on initial price
            db.session.commit()
        time.sleep(3)  # Adjust prices every 3 seconds

# Start the fluctuation in a separate thread
threading.Thread(target=fluctuate_stock_prices, daemon=True).start()

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

# -------------------- Password Reset Functions --------------------
def generate_reset_token(email, salt='password-reset-salt'):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=salt)

def verify_reset_token(token, expiration=3600, salt='password-reset-salt'):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt=salt, max_age=expiration)
    except Exception:
        return None
    return email

@app.template_filter('currency')
def currency_format(value):
    """Formats a number as currency (e.g., $1,234.56)."""
    try:
        return "${:,.2f}".format(float(value))
    except (ValueError, TypeError):
        return value

# Load environment variables
load_dotenv()

# -------------------- Routes --------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        fullname = request.form.get('fullname')
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        if Users.query.filter_by(username=username).first():
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))
        if Users.query.filter_by(email=email).first():
            flash('Email already registered. Please use a different email.', 'danger')
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = Users(fullname=fullname, username=username, email=email, password=hashed_password, role="user")
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = Users.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash(f'Welcome, {user.fullname}!', 'success')
            return redirect(url_for('portfolio'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/')
def home():
    return render_template('home.html', current_user=current_user)

@app.route('/about')
def about():
    return render_template('about.html', title='About')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        flash(f'Thank you {name}, we have received your message!', 'success')
        return redirect(url_for('home'))
    return render_template('contact.html', title='Contact')

# -------------------- Password Reset Routes --------------------
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if request.method == 'POST':
        email = request.form.get('email')
        user = Users.query.filter_by(email=email).first()
        if user:
            token = generate_reset_token(email)
            flash('A password reset link has been sent to your email. (For demo, you are being redirected.)', 'info')
            return redirect(url_for('reset_token', token=token))
        else:
            flash('No account found with that email.', 'danger')
            return redirect(url_for('login'))
    return render_template('reset_request.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    email = verify_reset_token(token)
    if not email:
        flash('The reset link is invalid or has expired.', 'danger')
        return redirect(url_for('reset_request'))
    if request.method == 'POST':
        password = request.form.get('password')
        confirm = request.form.get('confirm_password')
        if password != confirm:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('reset_token', token=token))
        user = Users.query.filter_by(email=email).first()
        if user:
            user.password = generate_password_hash(password, method='pbkdf2:sha256')
            db.session.commit()
            flash('Your password has been updated. Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('reset_token.html', token=token)
# -------------------- End Password Reset Routes --------------------_


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "admin":
            flash("You do not have permission to access this page.", "danger")
            return redirect(url_for("unauthorized"))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/unauthorized')
def unauthorized():
    return render_template('unauthorized.html'), 403

# -------------------- Other Routes --------------------
@app.route('/update-market-times', methods=['POST'])
@login_required
@admin_required
def update_market_times():
    start_time = request.form.get('start_time')
    end_time = request.form.get('end_time')
    day_start = request.form.get('day_start')
    day_end = request.form.get('day_end')

    # Validate inputs
    if not start_time or not end_time or not day_start or not day_end:
        flash('All fields are required. Please fill out the form completely.', 'danger')
        return redirect(url_for('admin'))

    market_times = Admin.query.first()
    if market_times:
        market_times.start_time = start_time
        market_times.end_time = end_time
        market_times.day_start = day_start
        market_times.day_end = day_end
    else:
        market_times = Admin(
            start_time=start_time,
            end_time=end_time,
            day_start=day_start,
            day_end=day_end
        )
        db.session.add(market_times)
    db.session.commit()
    flash('Market times updated successfully!', 'success')
    return redirect(url_for('admin'))

@app.route('/update-fluctuation', methods=['POST'])
@login_required
@admin_required
def update_fluctuation():
    fluctuation = request.form.get('fluctuation')

    # Validate input
    try:
        fluctuation = float(fluctuation)
        if fluctuation < 0:
            raise ValueError("Fluctuation cannot be negative.")
    except ValueError:
        flash('Invalid fluctuation value. Please enter a valid non-negative number.', 'danger')
        return redirect(url_for('admin'))

    market_times = Admin.query.first()
    if market_times:
        market_times.fluctuation = fluctuation
    else:
        market_times = Admin(
            start_time="09:00:00",
            end_time="16:00:00",
            day_start="Monday",
            day_end="Friday",
            fluctuation=fluctuation
        )
        db.session.add(market_times)
    db.session.commit()
    flash('Fluctuation percentage updated successfully!', 'success')
    return redirect(url_for('admin'))

# -------------------- Admin--------------------

@app.route('/admin')
@login_required
@admin_required
def admin():
    users = Users.query.all()
    market_times = Admin.query.first()
    stocks = Stock.query.all()  # Fetch all stocks
    return render_template("admin.html", users=users, market_times=market_times, stocks=stocks)

@app.route('/delete-user/<int:user_id>', methods=["POST"])
@login_required
@admin_required
def delete_user(user_id):
    user = Users.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully.', 'success')
    return redirect(url_for('admin'))

@app.route('/change-role/<int:user_id>', methods=["POST"])
@login_required
@admin_required
def change_role(user_id):
    user = Users.query.get_or_404(user_id)
    new_role = request.form.get("role")
    if new_role in ["user", "admin"]:
        user.role = new_role
        db.session.commit()
        flash('User role updated successfully.', 'success')
    return redirect(url_for('admin'))

# -------------------- Portfolio --------------------
@app.route('/portfolio')
@login_required
def portfolio():
    user_transactions = Transaction.query.filter_by(user_id=current_user.id).all()

    holdings = {}
    total_value = 0.0

    # First pass: Calculate total shares and total cost for buy transactions only
    for tx in user_transactions:
        sid = tx.stock_id
        if sid not in holdings:
            holdings[sid] = {"shares": 0, "total_cost": 0.0, "total_bought": 0, "total_spent": 0.0}
        
        if tx.transaction_type == 'buy':
            holdings[sid]["total_bought"] += tx.shares
            holdings[sid]["total_spent"] += tx.shares * tx.price
        
        # Update current shares count
        if tx.transaction_type == 'buy':
            holdings[sid]["shares"] += tx.shares
        else:
            holdings[sid]["shares"] -= tx.shares

    portfolio_holdings = []
    for sid, data in holdings.items():
        if data["shares"] > 0:  # Only process stocks we still own
            stock = Stock.query.get(sid)
            current_price = stock.live_price  # Use live price
            
            # Calculate true average purchase price based on all buys
            avg_price = data["total_spent"] / data["total_bought"] if data["total_bought"] > 0 else 0
            current_value = data["shares"] * current_price
            total_value += current_value

            portfolio_holdings.append({
                "symbol": stock.symbol,
                "shares": data["shares"],
                "avg_price": round(avg_price, 2),
                "total_value": round(current_value, 2)
            })

    updated_balance = Users.query.get(current_user.id).balance
    market_times = Admin.query.first()

    portfolio_data = {
        "total_value": round(total_value + updated_balance, 2),
        "cash": round(updated_balance, 2),
        "num_stocks": len(portfolio_holdings),
        "total_shares": sum(h["shares"] for h in portfolio_holdings),
        "holdings": portfolio_holdings,
        "market_start_time": market_times.start_time.strftime("%H:%M:%S") if market_times else "N/A",
        "market_end_time": market_times.end_time.strftime("%H:%M:%S") if market_times else "N/A",
        "market_day_start": market_times.day_start if market_times else "N/A",
        "market_day_end": market_times.day_end if market_times else "N/A"
    }

    return render_template('portfolio.html', title='Portfolio', portfolio_data=portfolio_data)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        fullname = request.form.get('fullname')
        email = request.form.get('email')
        user = Users.query.get(current_user.id)
        user.fullname = fullname
        user.email = email
        db.session.commit()
        flash('Profile updated successfully.', 'success')
    return render_template('profile.html', title='Profile', user=current_user)
# -------------------- Transactions --------------------

@app.route('/transactions')
@login_required
def transactions():
    txs = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.transaction_date.desc()).all()
    transactions_list = []
    for tx in txs:
        stock = Stock.query.get(tx.stock_id)
        transactions_list.append({
            "symbol": stock.symbol,  # Updated to use symbol
            "transaction_type": tx.transaction_type,
            "shares": tx.shares,
            "price": tx.price,
            "transaction_date": tx.transaction_date
        })
    # Recalculate total account value from holdings.
    user_transactions = Transaction.query.filter_by(user_id=current_user.id).all()
    holdings = {}
    for tx in user_transactions:
        sid = tx.stock_id
        if sid not in holdings:
            holdings[sid] = {"shares": 0, "total_cost": 0.0}
        if tx.transaction_type == 'buy':
            holdings[sid]["shares"] += tx.shares
            holdings[sid]["total_cost"] += tx.shares * tx.price
        elif tx.transaction_type == 'sell':
            holdings[sid]["shares"] -= tx.shares
            holdings[sid]["total_cost"] -= tx.shares * tx.price
    total_value = 0.0
    for sid, data in holdings.items():
        if data["shares"] > 0:
            avg_price = data["total_cost"] / data["shares"]
            total_value += data["shares"] * avg_price
    return render_template('transactions.html', title='Transactions', transactions=transactions_list, total_value=round(total_value, 2))

@app.route('/add-funds', methods=['POST'])
@login_required
def add_funds():
    try:
        amount = float(request.form.get('amount'))
    except ValueError:
        flash('Invalid amount entered.', 'danger')
        return redirect(url_for('portfolio'))

    if amount <= 0:
        flash('Please enter a positive amount.', 'danger')
        return redirect(url_for('portfolio'))

    current_user.balance += amount  # Update the user's balance
    db.session.commit()

    flash(f"Successfully added ${amount:,.2f} to your account.", "success")
    return redirect(url_for('portfolio'))


from flask import jsonify, request

def is_us_holiday():
    today = date.today()
    holidays = {
        # Format: date(YYYY, MM, DD): "Holiday Name"
        date(today.year, 1, 1): "New Year's Day",
        date(today.year, 1, 17): "Martin Luther King Jr. Day",  # Third Monday in January
        date(today.year, 2, 21): "Presidents Day",  # Third Monday in February
        date(today.year, 5, 29): "Memorial Day",  # Last Monday in May
        date(today.year, 6, 19): "Juneteenth",
        date(today.year, 7, 4): "Independence Day",
        date(today.year, 9, 4): "Labor Day",  # First Monday in September
        date(today.year, 11, 23): "Thanksgiving Day",  # Fourth Thursday in November
        date(today.year, 12, 25): "Christmas Day"
    }
    return holidays.get(today)

@app.route('/stocks')
@login_required
def stocks():
    stocks_query = Stock.query.all()
    stocks_list = []
    market_times = Admin.query.first()
    holiday = is_us_holiday()  # Get holiday information

    for stock in stocks_query:
        stocks_list.append({
            "id": stock.id,
            "symbol": stock.symbol,
            "name": stock.name,
            "price": stock.live_price
        })

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify(stocks_list)

    portfolio_data = {
        "market_start_time": market_times.start_time.strftime("%H:%M:%S") if market_times else "09:00:00",
        "market_end_time": market_times.end_time.strftime("%H:%M:%S") if market_times else "16:00:00",
        "market_day_start": market_times.day_start if market_times else "Monday",
        "market_day_end": market_times.day_end if market_times else "Friday",
        "holiday": holiday  # Add holiday information to portfolio_data
    }

    return render_template('stocks.html', title='Stocks', stocks=stocks_list, portfolio_data=portfolio_data)

def is_market_open():
    now = datetime.now()
    current_day = now.strftime('%A')
    current_time = now.strftime('%H:%M:%S')
    
    market_times = Admin.query.first()
    if not market_times:
        print("No market times found")
        return False

    # Debug logging
    print(f"Current day: {current_day}, time: {current_time}")
    print(f"Market days: {market_times.day_start} to {market_times.day_end}")
    print(f"Market hours: {market_times.start_time} to {market_times.end_time}")

    days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']
    current_day_index = days.index(current_day)
    start_day_index = days.index(market_times.day_start)
    end_day_index = days.index(market_times.day_end)

    # Check if the current day is within market days
    day_is_valid = False
    if start_day_index <= end_day_index:
        day_is_valid = start_day_index <= current_day_index <= end_day_index
    else:  # Market crosses Sunday (e.g., Thurs to Mon)
        day_is_valid = current_day_index >= start_day_index or current_day_index <= end_day_index

    if not day_is_valid:
        print("Market is closed - not a trading day")
        return False

    # Convert times to comparable format
    market_start = market_times.start_time.strftime('%H:%M:%S')
    market_end = market_times.end_time.strftime('%H:%M:%S')

    # Check if current time is within market hours
    time_is_valid = False
    if market_start <= market_end:
        time_is_valid = market_start <= current_time <= market_end
    else:  # Market crosses midnight
        time_is_valid = current_time >= market_start or current_time <= market_end

    print(f"Market is {'open' if time_is_valid else 'closed'} - time check")
    return time_is_valid

@app.route('/buy-stock/<int:stock_id>', methods=['POST'])
@login_required
def buy_stock(stock_id):
    if not is_market_open():
        return jsonify({"error": "Market is currently closed"}), 400
        
    stock = Stock.query.get_or_404(stock_id)
    
    try:
        shares = int(request.form.get("shares"))
    except (ValueError, TypeError):
        flash("Invalid input. Please enter a valid number of shares.", "danger")
        return redirect(url_for("stocks"))

    if shares <= 0:
        flash("You must buy at least one share.", "danger")
        return redirect(url_for("stocks"))

    current_price = stock.live_price  # Use live price
    total_cost = round(current_price * shares, 2)
    user = Users.query.get(current_user.id)

    if user.balance < total_cost:
        return jsonify({"error": "Insufficient funds"}), 400

    # Deduct the total cost from the user's balance
    user.balance -= total_cost

    # Create and add the transaction to the database
    new_transaction = Transaction(
        user_id=user.id,
        stock_id=stock.id,
        shares=shares,
        price=current_price,  # Use the live price
        transaction_type="buy"
    )

    db.session.add(new_transaction)
    db.session.commit()

    flash(f"Bought {shares} shares of {stock.symbol} at ${current_price:.2f} per share!", "success")
    return jsonify({
        "stock_name": stock.symbol,
        "stock_price": current_price,
        "shares": shares,
        "total_cost": total_cost
    })


@app.route('/sell-stock/<int:stock_id>', methods=['POST'])
@login_required
def sell_stock(stock_id):
    stock = Stock.query.get_or_404(stock_id)

    total_buys = db.session.query(db.func.sum(Transaction.shares)).filter_by(user_id=current_user.id, stock_id=stock.id, transaction_type='buy').scalar() or 0
    total_sells = db.session.query(db.func.sum(Transaction.shares)).filter_by(user_id=current_user.id, stock_id=stock.id, transaction_type='sell').scalar() or 0
    holdings = total_buys - total_sells

    try:
        shares = int(request.form.get('shares'))
    except ValueError:
        return jsonify({"error": "Invalid input. Enter a valid number of shares."}), 400

    if shares <= 0:
        return jsonify({"error": "Number of shares must be positive."}), 400

    if shares > holdings:
        return jsonify({"error": f"Insufficient shares. You own {holdings} shares."}), 400

    price = stock.live_price  # Use live price
    total_value = round(price * shares, 2)

    # Add the total value of the sold stock to the user's balance
    current_user.balance += total_value

    new_transaction = Transaction(user_id=current_user.id, stock_id=stock.id, shares=shares, price=price, transaction_type='sell')

    db.session.add(new_transaction)
    db.session.commit()
    return jsonify({
        "stock_name": stock.symbol,  # Updated to use symbol
        "stock_price": price,
        "shares": shares,
        "total_value": total_value
    })


@app.route('/create-stock', methods=["POST"])
@login_required
@admin_required
def create_stock():
    stock_name = request.form.get('stock_name')
    stock_symbol = request.form.get('stock_symbol')  # New field for symbol
    initial_price = request.form.get('initial_price')
    new_stock = Stock(name=stock_name, symbol=stock_symbol, initial_price=initial_price, live_price=initial_price)  # Updated to include symbol and live_price
    db.session.add(new_stock)
    db.session.commit()
    flash('Stock created successfully!', 'success')
    return redirect(url_for('admin'))

@app.route('/deposit-cash', methods=['POST'])
@login_required
def deposit_cash():
    try:
        amount = float(request.form.get('amount'))
    except ValueError:
        flash('Invalid amount entered.', 'danger')
        return redirect(url_for('portfolio'))

    if amount <= 0:
        flash('Please enter a positive amount.', 'danger')
        return redirect(url_for('portfolio'))

    current_user.balance += amount  # Update the user's balance
    db.session.commit()

    flash(f"Successfully deposited ${amount:,.2f} to your account.", "success")
    return redirect(url_for('portfolio'))


@app.route('/withdraw-cash', methods=['POST'])
@login_required
def withdraw_cash():
    try:
        amount = float(request.form.get('amount'))
    except ValueError:
        flash('Invalid amount entered.', 'danger')
        return redirect(url_for('portfolio'))

    if amount <= 0:
        flash('Please enter a positive amount.', 'danger')
        return redirect(url_for('portfolio'))

    if amount > current_user.balance:
        flash('Insufficient balance to withdraw this amount.', 'danger')
        return redirect(url_for('portfolio'))

    current_user.balance -= amount  # Deduct the amount from the user's balance
    db.session.commit()

    flash(f"Successfully withdrew ${amount:,.2f} from your account.", 'success')
    return redirect(url_for('portfolio'))
@app.route('/update-stock-price/<int:stock_id>', methods=['POST'])
@admin_required
def update_stock_price(stock_id):
    stock = Stock.query.get_or_404(stock_id)
    try:
        new_price = float(request.form.get('new_price'))
        if new_price <= 0:
            flash('Price must be greater than zero.', 'danger')
            return redirect(url_for('admin'))
    except ValueError:
        flash('Invalid price entered.', 'danger')
        return redirect(url_for('admin'))

    stock.initial_price = new_price
    db.session.commit()
    flash(f'Price for {stock.name} ({stock.symbol}) updated to ${new_price:.2f}.', 'success')
    return redirect(url_for('admin'))

