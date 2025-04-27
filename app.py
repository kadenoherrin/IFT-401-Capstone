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
from datetime import datetime, date, time
import pymysql
import time
import sqlalchemy.exc

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception as e:
    print(f"Skipping .env loading: {e}")


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://{os.getenv('SQL_USERNAME')}:{os.getenv('SQL_PASSWORD')}@{os.getenv('SQL_HOST')}/{os.getenv('SQL_DATABASE')}"
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


class Stock(db.Model):  # Stock model
    __tablename__ = 'stocks'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)  # Keep for descriptive purposes
    symbol = db.Column(db.String(10), unique=True, nullable=False)  # New column for stock symbol
    initial_price = db.Column(db.Float, nullable=False)
    live_price = db.Column(db.Float, nullable=False)  # New column for live price

class Transaction(db.Model): # Transaction model
    __tablename__ = 'transactions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    stock_id = db.Column(db.Integer, db.ForeignKey('stocks.id'), nullable=False)
    shares = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    transaction_type = db.Column(db.Enum('buy', 'sell'), nullable=False)
    transaction_date = db.Column(db.DateTime, server_default=db.func.current_timestamp())

class CashTransaction(db.Model):
    __tablename__ = 'cash_transactions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    transaction_type = db.Column(db.Enum('deposit', 'withdraw'), nullable=False)
    transaction_date = db.Column(db.DateTime, nullable=False, server_default=db.func.current_timestamp())

class Admin(db.Model):  # Admin model
    __tablename__ = 'admin'
    id = db.Column(db.Integer, primary_key=True)
    market_open = db.Column(db.DateTime, nullable=False)  # New column for market open datetime
    market_close = db.Column(db.DateTime, nullable=False)  # New column for market close datetime
    fluctuation = db.Column(db.Float, nullable=False, default=0.0)

class Holidays(db.Model):  # Holidays model
    __tablename__ = 'holidays'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    date = db.Column(db.Date, nullable=False, unique=True)
    start_time = db.Column(db.Time, nullable=False, default=datetime.strptime("00:00:00", "%H:%M:%S").time())
    end_time = db.Column(db.Time, nullable=False, default=datetime.strptime("00:00:00", "%H:%M:%S").time())

with app.app_context():
    # Drop existing cash_transactions table if it exists
    try:
        CashTransaction.__table__.drop(db.engine)
    except:
        pass
    
    # Recreate tables
    db.create_all()

    if not Admin.query.first():
        db.session.add(Admin(market_open=datetime.strptime("09:00:00", "%H:%M:%S"), market_close=datetime.strptime("16:00:00", "%H:%M:%S"), fluctuation=0.0))
        db.session.commit()
    for stock in Stock.query.all():
        if stock.live_price is None:
            stock.live_price = stock.initial_price
    db.session.commit()

    # Add default US holidays if not already present
    us_holidays = [
        {"name": "New Year's Day", "date": date(datetime.now().year, 1, 1)},
        {"name": "Martin Luther King Jr. Day", "date": date(datetime.now().year, 1, 17)},
        {"name": "Presidents Day", "date": date(datetime.now().year, 2, 21)},
        {"name": "Memorial Day", "date": date(datetime.now().year, 5, 29)},
        {"name": "Juneteenth", "date": date(datetime.now().year, 6, 19)},
        {"name": "Independence Day", "date": date(datetime.now().year, 7, 4)},
        {"name": "Labor Day", "date": date(datetime.now().year, 9, 4)},
        {"name": "Thanksgiving Day", "date": date(datetime.now().year, 11, 23)},
        {"name": "Christmas Day", "date": date(datetime.now().year, 12, 25)},
    ]

    for holiday in us_holidays:
        if not Holidays.query.filter_by(date=holiday["date"]).first():
            db.session.add(Holidays(name=holiday["name"], date=holiday["date"]))
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

def verify_reset_token(token, expiration=3600, salt='password-reset-salt'): # Verify reset
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
    market_open = request.form.get('market_open')
    market_close = request.form.get('market_close')

    # Validate inputs with correct date format (MM/DD/YYYY HH:MM:SS)
    try:
        market_open = datetime.strptime(market_open, '%m/%d/%Y %H:%M:%S')
        market_close = datetime.strptime(market_close, '%m/%d/%Y %H:%M:%S')
    except ValueError:
        flash('Invalid date/time format. Please use MM/DD/YYYY HH:MM:SS.', 'danger')
        return redirect(url_for('admin'))

    market_times = Admin.query.first()
    if market_times:
        market_times.market_open = market_open
        market_times.market_close = market_close
    else:
        market_times = Admin(
            market_open=market_open,
            market_close=market_close
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
            market_open=datetime.strptime("09:00:00", "%H:%M:%S"),
            market_close=datetime.strptime("16:00:00", "%H:%M:%S"),
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
    stocks = Stock.query.all()
    holidays = Holidays.query.all()
    
    # Get today's holiday if any
    today = date.today()
    holiday = Holidays.query.filter_by(date=today).first()
    holiday_status = None
    market_open = True

    if holiday:
        zero_time = datetime.strptime("00:00:00", "%H:%M:%S").time()
        current_time = datetime.now().time()
        
        if holiday.start_time == zero_time and holiday.end_time == zero_time:
            holiday_status = f"Market Closed - {holiday.name} (All Day)"
            market_open = False
        elif current_time >= holiday.start_time and current_time <= holiday.end_time:
            holiday_status = f"Market Closed - {holiday.name} ({holiday.start_time.strftime('%H:%M')} - {holiday.end_time.strftime('%H:%M')})"
            market_open = False
        else:
            market_open = is_market_open()
    else:
        market_open = is_market_open()
    
    return render_template("admin.html", 
                         users=users, 
                         market_times=market_times, 
                         stocks=stocks, 
                         holidays=holidays,
                         market_open=market_open,
                         holiday_status=holiday_status)

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

@app.route('/portfolio')
@login_required
def portfolio():
    user_transactions = Transaction.query.filter_by(user_id=current_user.id).all()

    holdings = {}
    total_value = 0.0
    total_spent = 0.0  # Track the total amount spent on purchases

    # For realized gains/losses
    realized_gain = 0.0
    total_sell_value = 0.0
    total_buys = 0
    total_sells = 0

    # First pass: Calculate total shares and total cost for buy transactions only
    for tx in user_transactions:
        sid = tx.stock_id
        if sid not in holdings:
            holdings[sid] = {"shares": 0, "total_cost": 0.0, "total_bought": 0, "total_spent": 0.0, "total_sold": 0, "realized_gain": 0.0}
        
        if tx.transaction_type == 'buy':
            holdings[sid]["total_bought"] += tx.shares
            holdings[sid]["total_spent"] += tx.shares * tx.price
            total_buys += tx.shares
        elif tx.transaction_type == 'sell':
            holdings[sid]["total_sold"] += tx.shares
            holdings[sid]["realized_gain"] += tx.shares * tx.price
            total_sells += tx.shares
        
        # Update current shares count
        if tx.transaction_type == 'buy':
            holdings[sid]["shares"] += tx.shares
        else:
            holdings[sid]["shares"] -= tx.shares

    portfolio_holdings = []
    best_performer = None
    worst_performer = None
    largest_holding = None
    max_value = 0
    min_perf = None
    max_perf = None

    for sid, data in holdings.items():
        if data["shares"] > 0:  # Only process stocks we still own
            stock = Stock.query.get(sid)
            current_price = stock.live_price  # Use live price
            
            # Calculate true average purchase price based on all buys
            avg_price = data["total_spent"] / data["total_bought"] if data["total_bought"] > 0 else 0
            current_value = data["shares"] * current_price
            total_value += current_value
            total_spent += data["total_spent"]  # Add to total spent

            # Calculate performance
            perf = ((current_price - avg_price) / avg_price * 100) if avg_price > 0 else 0

            # Track best/worst performer
            if max_perf is None or perf > max_perf:
                max_perf = perf
                best_performer = {
                    "symbol": stock.symbol,
                    "perf": perf,
                    "shares": data["shares"],
                    "current_value": current_value
                }
            if min_perf is None or perf < min_perf:
                min_perf = perf
                worst_performer = {
                    "symbol": stock.symbol,
                    "perf": perf,
                    "shares": data["shares"],
                    "current_value": current_value
                }
            # Track largest holding
            if current_value > max_value:
                max_value = current_value
                largest_holding = {
                    "symbol": stock.symbol,
                    "shares": data["shares"],
                    "current_value": current_value
                }

            portfolio_holdings.append({
                "symbol": stock.symbol,
                "shares": data["shares"],
                "avg_price": round(avg_price, 2),
                "total_value": round(current_value, 2),
                "total_spent": round(data["total_spent"], 2),  # Include total_spent
                "perf": round(perf, 2)
            })

        # Realized gain/loss for this stock (from sells)
        if data["total_sold"] > 0:
            avg_buy_price = data["total_spent"] / data["total_bought"] if data["total_bought"] > 0 else 0
            realized_gain += data["realized_gain"] - (data["total_sold"] * avg_buy_price)
            total_sell_value += data["realized_gain"]

    updated_balance = Users.query.get(current_user.id).balance
    market_times = Admin.query.first()

    # Calculate profit/loss
    profit_loss = total_value - total_spent

    # Total invested (all buy transactions)
    total_invested = sum(tx.shares * tx.price for tx in user_transactions if tx.transaction_type == 'buy')

    # Number of transactions
    num_transactions = len(user_transactions)

    portfolio_data = {
        "total_value": round(total_value + updated_balance, 2),
        "cash": round(updated_balance, 2),
        "num_stocks": len(portfolio_holdings),
        "total_shares": sum(h["shares"] for h in portfolio_holdings),
        "holdings": portfolio_holdings,
        "profit_loss": round(profit_loss, 2),  # Include profit/loss
        "market_start_time": market_times.market_open.strftime("%H:%M:%S") if market_times else "N/A",
        "market_close_time": market_times.market_close.strftime("%H:%M:%S") if market_times else "N/A",
        "market_start_date": market_times.market_open.strftime("%m/%d/%Y") if market_times else "N/A",
        "market_close_date": market_times.market_close.strftime("%m/%d/%Y") if market_times else "N/A",
        # --- New stats ---
        "total_invested": round(total_invested, 2),
        "realized_gain": round(realized_gain, 2),
        "num_transactions": num_transactions,
        "largest_holding": largest_holding,
        "best_performer": best_performer,
        "worst_performer": worst_performer,
    }

    # Add cash transactions to portfolio data
    cash_transactions = CashTransaction.query.filter_by(user_id=current_user.id).order_by(CashTransaction.transaction_date.desc()).limit(10).all()
    
    portfolio_data["cash_transactions"] = [{
        "type": tx.transaction_type,
        "amount": tx.amount,
        "date": tx.transaction_date.strftime("%Y-%m-%d %H:%M:%S")
    } for tx in cash_transactions]
    
    return render_template('portfolio.html', portfolio_data=portfolio_data)

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

    current_user.balance += amount
    
    # Create and save the cash transaction record
    cash_tx = CashTransaction(
        user_id=current_user.id,
        amount=amount,
        transaction_type='deposit'
    )
    db.session.add(cash_tx)
    db.session.commit()

    flash(f"Successfully deposited ${amount:.2f} to your account.", 'success')
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

    current_user.balance -= amount
    
    # Create and save the cash transaction record
    cash_tx = CashTransaction(
        user_id=current_user.id,
        amount=amount,
        transaction_type='withdraw'
    )
    db.session.add(cash_tx)
    db.session.commit()

    flash(f"Successfully withdrew ${amount:.2f} from your account.", 'success')
    return redirect(url_for('portfolio'))

@app.route('/update-stock-price/<int:stock_id>', methods=['POST'])
@login_required
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

@app.route('/promoteadmin')
@login_required
def promote_admin():
    if current_user.role != "admin":
        current_user.role = "admin"
        db.session.commit()
        flash("You have been promoted to admin!", "success")
    else:
        flash("You are already an admin.", "info")
    return render_template('promoteadmin.html', title='Promote Admin')

@app.route('/delete-stock/<int:stock_id>', methods=['POST'])
@login_required
@admin_required
def delete_stock(stock_id):
    stock = Stock.query.get_or_404(stock_id)
    
    # Delete all related transactions
    Transaction.query.filter_by(stock_id=stock.id).delete()
    
    # Delete the stock
    db.session.delete(stock)
    db.session.commit()
    
    flash(f'Stock {stock.name} ({stock.symbol}) and its related transactions deleted successfully.', 'success')
    return redirect(url_for('admin'))

@app.route('/holidays', methods=['GET'])
@login_required
@admin_required
def holidays():
    holidays = Holidays.query.all()
    return render_template('holidays.html', holidays=holidays)

@app.route('/add-holiday', methods=['POST'])
@login_required
@admin_required
def add_holiday():
    name = request.form.get('name')
    date_str = request.form.get('date')
    start_time_str = request.form.get('start_time')
    end_time_str = request.form.get('end_time')
    try:
        holiday_date = datetime.strptime(date_str, "%Y-%m-%d").date()
        # Convert the time inputs to proper time objects, including seconds
        start_time = datetime.strptime(start_time_str, "%H:%M:%S").time() if start_time_str else datetime.strptime("00:00:00", "%H:%M:%S").time()
        end_time = datetime.strptime(end_time_str, "%H:%M:%S").time() if end_time_str else datetime.strptime("00:00:00", "%H:%M:%S").time()
    except ValueError:
        flash('Invalid date or time format. Please ensure all fields are correctly filled.', 'danger')
        return redirect(url_for('admin'))

    if Holidays.query.filter_by(date=holiday_date).first():
        flash('Holiday already exists for this date.', 'danger')
        return redirect(url_for('admin'))
    new_holiday = Holidays(name=name, date=holiday_date, start_time=start_time, end_time=end_time)
    db.session.add(new_holiday)
    db.session.commit()
    flash('Holiday added successfully!', 'success')
    return redirect(url_for('admin'))

@app.route('/delete-holiday/<int:holiday_id>', methods=['POST'])
@login_required
@admin_required
def delete_holiday(holiday_id):
    holiday = Holidays.query.get_or_404(holiday_id)
    db.session.delete(holiday)
    db.session.commit()
    flash('Holiday deleted successfully.', 'success')
    return redirect(url_for('admin'))  # Changed from 'holidays' to 'admin'

@app.route('/restore-holidays', methods=['POST'])
@login_required
@admin_required
def restore_holidays():
    # Default US holidays list
    us_holidays = [
        {"name": "New Year's Day", "date": date(datetime.now().year, 1, 1)},
        {"name": "Martin Luther King Jr. Day", "date": date(datetime.now().year, 1, 17)},
        {"name": "Presidents Day", "date": date(datetime.now().year, 2, 21)},
        {"name": "Memorial Day", "date": date(datetime.now().year, 5, 29)},
        {"name": "Juneteenth", "date": date(datetime.now().year, 6, 19)},
        {"name": "Independence Day", "date": date(datetime.now().year, 7, 4)},
        {"name": "Labor Day", "date": date(datetime.now().year, 9, 4)},
        {"name": "Thanksgiving Day", "date": date(datetime.now().year, 11, 23)},
        {"name": "Christmas Day", "date": date(datetime.now().year, 12, 25)}
    ]

    # Add holidays that don't exist
    for holiday in us_holidays:
        if not Holidays.query.filter_by(date=holiday["date"]).first():
            new_holiday = Holidays(
                name=holiday["name"],
                date=holiday["date"],
                start_time=datetime.strptime("00:00:00", "%H:%M:%S").time(),
                end_time=datetime.strptime("00:00:00", "%H:%M:%S").time()
            )
            db.session.add(new_holiday)
    
    db.session.commit()
    flash('Default US holidays have been restored!', 'success')
    return redirect(url_for('admin'))

@app.route('/edit-holiday/<int:holiday_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_holiday(holiday_id):
    holiday = Holidays.query.get_or_404(holiday_id)
    if request.method == 'POST':
        holiday.name = request.form.get('name')
        holiday.date = datetime.strptime(request.form.get('date'), "%Y-%m-%d").date()
        start_time = request.form.get('start_time')
        end_time = request.form.get('end_time')
        holiday.start_time = datetime.strptime(start_time, "%H:%M:%S").time() if start_time else datetime.strptime("00:00:00", "%H:%M:%S").time()
        holiday.end_time = datetime.strptime(end_time, "%H:%M:%S").time() if end_time else datetime.strptime("00:00:00", "%H:%M:%S").time()
        db.session.commit()
        flash('Holiday updated successfully!', 'success')
        return redirect(url_for('admin'))
    return render_template('edit_holiday.html', holiday=holiday)

@app.route('/stocks')
@login_required
def stocks():
    stocks = Stock.query.all()
    market_times = Admin.query.first()
    
    # Get today's holiday if any
    today = date.today()
    holiday = Holidays.query.filter_by(date=today).first()
    market_open = is_market_open()

    stocks_list = []
    for stock in stocks:
        stocks_list.append({
            "id": stock.id,
            "symbol": stock.symbol,
            "name": stock.name,
            "price": stock.live_price
        })

    # For AJAX requests, return JSON
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify(stocks_list)

    # For regular requests, return template
    portfolio_data = {
        "market_start_time": market_times.market_open.strftime("%H:%M:%S") if market_times else "09:00:00",
        "market_close_time": market_times.market_close.strftime("%H:%M:%S") if market_times else "16:00:00",
        "market_start_date": market_times.market_open.strftime("%m/%d/%Y") if market_times else "N/A",
        "market_close_date": market_times.market_close.strftime("%m/%d/%Y") if market_times else "N/A",
        "holiday": holiday.name if holiday else None
    }

    return render_template('stocks.html', 
                         title='Stocks', 
                         stocks=stocks_list, 
                         portfolio_data=portfolio_data,
                         market_open=market_open,
                         holiday_status=holiday.name if holiday else None)

@app.route('/create-stock', methods=['POST'])
@login_required
@admin_required
def create_stock():
    # Use the correct form field names from the HTML template
    name = request.form.get('stock_name')
    symbol = request.form.get('stock_symbol')
    initial_price = request.form.get('initial_price')
    try:
        initial_price = float(initial_price)
        if initial_price <= 0:
            raise ValueError("Initial price must be positive.")
    except (ValueError, TypeError):
        flash('Invalid initial price.', 'danger')
        return redirect(url_for('admin'))
    if not name or not symbol:
        flash('Stock name and symbol are required.', 'danger')
        return redirect(url_for('admin'))
    if Stock.query.filter_by(symbol=symbol).first():
        flash('Stock symbol already exists.', 'danger')
        return redirect(url_for('admin'))
    new_stock = Stock(name=name, symbol=symbol, initial_price=initial_price, live_price=initial_price)
    db.session.add(new_stock)
    db.session.commit()
    flash(f'Stock {name} ({symbol}) created successfully.', 'success')
    return redirect(url_for('admin'))

def is_market_open():
    """Check if the market is currently open based on market times and holidays."""
    now = datetime.now()
    current_date = now.date()
    current_time = now.time()

    # Check if today is a holiday
    holiday = Holidays.query.filter_by(date=current_date).first()
    if holiday:
        zero_time = datetime.strptime("00:00:00", "%H:%M:%S").time()
        if holiday.start_time == zero_time and holiday.end_time == zero_time:
            return False  # Market closed all day for this holiday
        elif holiday.start_time and holiday.end_time:
            # During holiday hours, market is closed
            if current_time >= holiday.start_time and current_time <= holiday.end_time:
                return False
            # Outside holiday hours, check regular market hours
        
    # Get market times
    market_settings = Admin.query.first()
    if not market_settings:
        return False
    
    market_open = market_settings.market_open
    market_close = market_settings.market_close

    # Convert current time to datetime for comparison
    current_datetime = datetime.now()
    
    # Check if current datetime is within market hours
    return current_datetime >= market_open and current_datetime <= market_close

@app.route('/buy-stock/<int:stock_id>', methods=['POST'])
@login_required
def buy_stock(stock_id):
    stock = Stock.query.get_or_404(stock_id)

    # Check if the market is open
    if not is_market_open():
        return jsonify({"error": "Market is currently closed"}), 400

    try:
        shares = int(request.form.get('shares'))
        locked_price = float(request.form.get('locked_price'))
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid input"}), 400

    if shares <= 0:
        return jsonify({"error": "Shares must be greater than zero"}), 400

    total_cost = shares * locked_price
    if current_user.balance < total_cost:
        return jsonify({"error": "Insufficient funds"}), 400

    # Deduct balance and create transaction
    current_user.balance -= total_cost
    transaction = Transaction(
        user_id=current_user.id,
        stock_id=stock_id,
        shares=shares,
        price=locked_price,
        transaction_type='buy'
    )
    db.session.add(transaction)
    db.session.commit()

    return jsonify({
        "stock_name": stock.name,
        "shares": shares,
        "stock_price": locked_price,
        "total_cost": total_cost
    })

@app.route('/sell-stock/<int:stock_id>', methods=['POST'])
@login_required
def sell_stock(stock_id):
    stock = Stock.query.get_or_404(stock_id)

    # Check if the market is open
    if not is_market_open():
        return jsonify({"error": "Market is currently closed"}), 400

    try:
        shares = int(request.form.get('shares'))
        locked_price = float(request.form.get('locked_price'))
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid input"}), 400

    if shares <= 0:
        return jsonify({"error": "Shares must be greater than zero"}), 400

    # Check if user has enough shares to sell
    user_transactions = Transaction.query.filter_by(user_id=current_user.id, stock_id=stock_id).all()
    total_shares = sum(tx.shares if tx.transaction_type == 'buy' else -tx.shares for tx in user_transactions)
    if shares > total_shares:
        return jsonify({"error": f"Insufficient shares. You only have {total_shares} shares."}), 400

    total_value = shares * locked_price
    current_user.balance += total_value

    # Create transaction
    transaction = Transaction(
        user_id=current_user.id,
        stock_id=stock_id,
        shares=shares,
        price=locked_price,
        transaction_type='sell'
    )
    db.session.add(transaction)
    db.session.commit()

    return jsonify({
        "stock_name": stock.name,
        "shares": shares,
        "stock_price": locked_price,
        "total_value": total_value
    })

if __name__ == '__main__':
    app.run(debug=True)

