# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
import requests
import uuid
import json

# Initialize SQLAlchemy outside of app creation
db = SQLAlchemy()

# Models
class User(db.Model):  # Changed from lowercase 'user' to 'User'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    balance = db.Column(db.Float, default=0.00)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    loans_requested = db.relationship('Loan', backref='requester', lazy=True,
                                    foreign_keys='Loan.requester_id')
    loans_funded = db.relationship('Loan', backref='funder', lazy=True,
                                foreign_keys='Loan.funder_id')
    transactions = db.relationship('Transaction', backref='user', lazy=True)

class Loan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    interest_rate = db.Column(db.Float, nullable=False)
    duration_months = db.Column(db.Integer, nullable=False)
    purpose = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, funded, repaid, defaulted
    requester_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    funder_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    funded_at = db.Column(db.DateTime)
    
    transactions = db.relationship('Transaction', backref='loan', lazy=True)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    transaction_type = db.Column(db.String(50), nullable=False)  # deposit, withdrawal, loan_request, loan_funding, repayment
    reference = db.Column(db.String(100), unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    loan_id = db.Column(db.Integer, db.ForeignKey('loan.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')  # pending, completed, failed

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'fuego_secret_key_should_be_changed_in_production'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///fuego.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Paystack configuration (replace with your actual keys)
    PAYSTACK_SECRET_KEY = "fuegosecret"
    PAYSTACK_PUBLIC_KEY = "fuegopublic"
    PAYSTACK_BASE_URL = "https://api.paystack.co"
    
    # Headers for Paystack API requests
    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json"
    }
    
    # Initialize the app with the extension
    db.init_app(app)
    
    # Create tables within app context
    with app.app_context():
        db.create_all()
    
    # Paystack helper functions
    def initialize_transaction(email, amount, reference=None, callback_url=None):
        """
        Initialize a Paystack transaction
        
        Args:
            email (str): Customer's email address
            amount (float): Amount in the smallest currency unit (kobo for NGN, cents for USD)
            reference (str, optional): Unique transaction reference. If None, one will be generated.
            callback_url (str, optional): URL to redirect to after payment
            
        Returns:
            dict: Response from Paystack API containing authorization URL
        """
        if reference is None:
            reference = f"FUEGO-{uuid.uuid4().hex[:8]}"
            
        # Convert amount to the smallest currency unit (e.g., cents)
        amount_in_cents = int(amount * 100)
        
        payload = {
            "email": email,
            "amount": amount_in_cents,
            "reference": reference
        }
        
        if callback_url:
            payload["callback_url"] = callback_url
        
        url = f"{PAYSTACK_BASE_URL}/transaction/initialize"
        
        try:
            response = requests.post(url, headers=headers, data=json.dumps(payload))
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"status": False, "message": str(e)}
    
    def verify_transaction(reference):
        """
        Verify the status of a transaction
        
        Args:
            reference (str): The transaction reference
            
        Returns:
            dict: Response from Paystack API containing transaction details
        """
        url = f"{PAYSTACK_BASE_URL}/transaction/verify/{reference}"
        
        try:
            response = requests.get(url, headers=headers)
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"status": False, "message": str(e)}
    
    def list_banks(country="nigeria"):
        """
        Get a list of banks supported by Paystack
        
        Args:
            country (str): Country code (default: "nigeria")
            
        Returns:
            dict: Response from Paystack API containing list of banks
        """
        url = f"{PAYSTACK_BASE_URL}/bank?country={country}"
        
        try:
            response = requests.get(url, headers=headers)
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"status": False, "message": str(e)}
    
    def verify_account(account_number, bank_code):
        """
        Verify a bank account
        
        Args:
            account_number (str): Account number
            bank_code (str): Bank code
            
        Returns:
            dict: Response from Paystack API containing account details
        """
        url = f"{PAYSTACK_BASE_URL}/bank/resolve?account_number={account_number}&bank_code={bank_code}"
        
        try:
            response = requests.get(url, headers=headers)
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"status": False, "message": str(e)}
    
    def create_transfer_recipient(account_number, bank_code, name):
        """
        Create a transfer recipient for bank transfers
        
        Args:
            account_number (str): Account number
            bank_code (str): Bank code
            name (str): Account name
            
        Returns:
            dict: Response from Paystack API containing recipient code
        """
        url = f"{PAYSTACK_BASE_URL}/transferrecipient"
        
        payload = {
            "type": "nuban",
            "name": name,
            "account_number": account_number,
            "bank_code": bank_code,
            "currency": "NGN"
        }
        
        try:
            response = requests.post(url, headers=headers, data=json.dumps(payload))
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"status": False, "message": str(e)}
    
    def initiate_transfer(amount, recipient_code, reason=None, reference=None):
        """
        Initiate a transfer to a recipient
        
        Args:
            amount (float): Amount in the smallest currency unit (kobo for NGN, cents for USD)
            recipient_code (str): Recipient code
            reason (str, optional): Reason for the transfer
            reference (str, optional): Unique transfer reference. If None, one will be generated.
            
        Returns:
            dict: Response from Paystack API containing transfer details
        """
        if reference is None:
            reference = f"FUEGO-TRF-{uuid.uuid4().hex[:8]}"
            
        # Convert amount to the smallest currency unit (e.g., cents)
        amount_in_cents = int(amount * 100)
        
        url = f"{PAYSTACK_BASE_URL}/transfer"
        
        payload = {
            "source": "balance",
            "amount": amount_in_cents,
            "recipient": recipient_code,
            "reference": reference
        }
        
        if reason:
            payload["reason"] = reason
        
        try:
            response = requests.post(url, headers=headers, data=json.dumps(payload))
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"status": False, "message": str(e)}
    
    # Routes
    @app.route('/')
    def index():
        if 'user_id' in session:
            return redirect(url_for('dashboard'))
        return render_template('index.html', paystack_public_key=PAYSTACK_PUBLIC_KEY)
    
    @app.route('/signup', methods=['GET', 'POST'])
    def signup():
        if request.method == 'POST':
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            
            # Input validation
            if not all([username, email, password, confirm_password]):
                flash('All fields are required', 'danger')
                return redirect(url_for('signup'))
                
            if password != confirm_password:
                flash('Passwords do not match', 'danger')
                return redirect(url_for('signup'))
                
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                flash('Username already exists', 'danger')
                return redirect(url_for('signup'))
                
            existing_email = User.query.filter_by(email=email).first()
            if existing_email:
                flash('Email already registered', 'danger')
                return redirect(url_for('signup'))
            
            # Create new user
            new_user = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password)
            )
            db.session.add(new_user)
            db.session.commit()
            
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
            
        return render_template('signup.html')
    
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            
            # Changed from lowercase 'user' to 'User'
            user = User.query.filter_by(username=username).first()
            
            if user and check_password_hash(user.password_hash, password):
                session['user_id'] = user.id
                session['username'] = user.username
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password', 'danger')
                
        return render_template('login.html')
    
    @app.route('/logout')
    def logout():
        session.pop('user_id', None)
        session.pop('username', None)
        flash('You have been logged out', 'success')
        return redirect(url_for('index'))
    
    @app.route('/dashboard')
    def dashboard():
        if 'user_id' not in session:
            flash('Please log in to access this page', 'danger')
            return redirect(url_for('login'))
            
        # Changed from lowercase 'user' to 'User'
        current_user = User.query.get(session['user_id'])
        loan_requests = Loan.query.filter_by(status='pending').all()
        my_loan_requests = Loan.query.filter_by(requester_id=current_user.id).all()
        my_funded_loans = Loan.query.filter_by(funder_id=current_user.id).all()
        
        return render_template('dashboard.html', 
                              user=current_user, 
                              loan_requests=loan_requests,
                              my_loan_requests=my_loan_requests,
                              my_funded_loans=my_funded_loans)
    
    @app.route('/request_loan', methods=['GET', 'POST'])
    def request_loan():
        if 'user_id' not in session:
            flash('Please log in to access this page', 'danger')
            return redirect(url_for('login'))
            
        if request.method == 'POST':
            amount = float(request.form.get('amount'))
            interest_rate = float(request.form.get('interest_rate'))
            duration_months = int(request.form.get('duration_months'))
            purpose = request.form.get('purpose')
            
            # Input validation
            if not all([amount, interest_rate, duration_months, purpose]):
                flash('All fields are required', 'danger')
                return redirect(url_for('request_loan'))
                
            if amount <= 0 or interest_rate <= 0 or duration_months <= 0:
                flash('Amount, interest rate, and duration must be positive', 'danger')
                return redirect(url_for('request_loan'))
            
            # Create loan request
            new_loan = Loan(
                amount=amount,
                interest_rate=interest_rate,
                duration_months=duration_months,
                purpose=purpose,
                requester_id=session['user_id']
            )
            db.session.add(new_loan)
            db.session.commit()
            
            # Record transaction
            transaction = Transaction(
                amount=amount,
                transaction_type='loan_request',
                reference=f"LOAN-REQ-{uuid.uuid4().hex[:8]}",
                user_id=session['user_id'],
                loan_id=new_loan.id,
                status='completed'
            )
            db.session.add(transaction)
            db.session.commit()
            
            flash('Loan request created successfully', 'success')
            return redirect(url_for('dashboard'))
            
        return render_template('request_loan.html')
    
    @app.route('/fund_loan/<int:loan_id>', methods=['GET', 'POST'])
    def fund_loan(loan_id):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'danger')
            return redirect(url_for('login'))
            
        loan = Loan.query.get_or_404(loan_id)
        # Changed from lowercase 'user' to 'User'
        current_user = User.query.get(session['user_id'])
        
        if loan.status != 'pending':
            flash('This loan is no longer available for funding', 'danger')
            return redirect(url_for('dashboard'))
            
        if loan.requester_id == session['user_id']:
            flash('You cannot fund your own loan request', 'danger')
            return redirect(url_for('dashboard'))
            
        if request.method == 'POST':
            if current_user.balance < loan.amount:
                flash('Insufficient balance to fund this loan', 'danger')
                return redirect(url_for('dashboard'))
                
            # Update loan status
            loan.status = 'funded'
            loan.funder_id = session['user_id']
            loan.funded_at = datetime.utcnow()
            
            # Update balances
            current_user.balance -= loan.amount
            # Changed from lowercase 'user' to 'User'
            requester = User.query.get(loan.requester_id)
            requester.balance += loan.amount
            
            # Record transactions
            funding_transaction = Transaction(
                amount=loan.amount,
                transaction_type='loan_funding',
                reference=f"LOAN-FUND-{uuid.uuid4().hex[:8]}",
                user_id=session['user_id'],
                loan_id=loan.id,
                status='completed'
            )
            
            receiving_transaction = Transaction(
                amount=loan.amount,
                transaction_type='loan_received',
                reference=f"LOAN-RECV-{uuid.uuid4().hex[:8]}",
                user_id=requester.id,
                loan_id=loan.id,
                status='completed'
            )
            
            db.session.add(funding_transaction)
            db.session.add(receiving_transaction)
            db.session.commit()
            
            flash('Loan funded successfully', 'success')
            return redirect(url_for('dashboard'))
            
        return render_template('fund_loan.html', loan=loan)
    
    @app.route('/transactions')
    def transactions():
        if 'user_id' not in session:
            flash('Please log in to access this page', 'danger')
            return redirect(url_for('login'))
            
        user_transactions = Transaction.query.filter_by(user_id=session['user_id']).order_by(Transaction.created_at.desc()).all()
        return render_template('transactions.html', transactions=user_transactions)
    
    @app.route('/deposit', methods=['GET', 'POST'])
    def deposit():
        if 'user_id' not in session:
            flash('Please log in to access this page', 'danger')
            return redirect(url_for('login'))
            
        if request.method == 'POST':
            amount = float(request.form.get('amount'))
            
            if amount <= 0:
                flash('Amount must be positive', 'danger')
                return redirect(url_for('deposit'))
                
            # Generate a unique reference
            reference = f"FUEGO-DEP-{uuid.uuid4().hex[:8]}"
            
            # In a real app, you would redirect to Paystack checkout
            # For this example, we'll simulate a successful deposit
            
            # Record the transaction
            transaction = Transaction(
                amount=amount,
                transaction_type='deposit',
                reference=reference,
                user_id=session['user_id'],
                status='completed'
            )
            db.session.add(transaction)
            
            # Update user balance
            # Changed from lowercase 'user' to 'User'
            current_user = User.query.get(session['user_id'])
            current_user.balance += amount
            
            db.session.commit()
            
            flash(f'Deposit of ₦{amount:.2f} successful', 'success')
            return redirect(url_for('dashboard'))
            
        return render_template('deposit.html', paystack_public_key=PAYSTACK_PUBLIC_KEY)
    
    @app.route('/withdraw', methods=['GET', 'POST'])
    def withdraw():
        if 'user_id' not in session:
            flash('Please log in to access this page', 'danger')
            return redirect(url_for('login'))
            
        # Changed from lowercase 'user' to 'User'
        current_user = User.query.get(session['user_id'])
        
        if request.method == 'POST':
            amount = float(request.form.get('amount'))
            
            if amount <= 0:
                flash('Amount must be positive', 'danger')
                return redirect(url_for('withdraw'))
                
            if amount > current_user.balance:
                flash('Insufficient balance', 'danger')
                return redirect(url_for('withdraw'))
                
            # Generate a unique reference
            reference = f"FUEGO-WTH-{uuid.uuid4().hex[:8]}"
            
            # In a real app, you would initiate a Paystack transfer
            # For this example, we'll simulate a successful withdrawal
            
            # Record the transaction
            transaction = Transaction(
                amount=amount,
                transaction_type='withdrawal',
                reference=reference,
                user_id=session['user_id'],
                status='completed'
            )
            db.session.add(transaction)
            
            # Update user balance
            current_user.balance -= amount
            
            db.session.commit()
            
            flash(f'Withdrawal of ₦{amount:.2f} successful', 'success')
            return redirect(url_for('dashboard'))
            
        return render_template('withdraw.html', user=current_user)
    
    @app.route('/verify_payment', methods=['GET'])
    def verify_payment():
        reference = request.args.get('reference')
        
        if not reference:
            flash('Payment reference not found', 'danger')
            return redirect(url_for('dashboard'))
        
        # In a real app, you would verify with Paystack API
        # For this example, we'll simulate a successful verification
        
        # Find the transaction
        transaction = Transaction.query.filter_by(reference=reference).first()
        
        if transaction and transaction.status == 'pending':
            transaction.status = 'completed'
            
            # Update user balance for deposits
            if transaction.transaction_type == 'deposit':
                # Changed from lowercase 'user' to 'User'
                current_user = User.query.get(transaction.user_id)
                current_user.balance += transaction.amount
                
            db.session.commit()
            flash('Payment verified successfully', 'success')
        
        return redirect(url_for('dashboard'))
    
    # Paystack webhook endpoint
    @app.route('/paystack/webhook', methods=['POST'])
    def paystack_webhook():
        # In a real app, you would verify the signature
        
        payload = request.get_json()
        event = payload.get('event')
        
        if event == 'charge.success':
            data = payload.get('data', {})
            reference = data.get('reference')
            
            transaction = Transaction.query.filter_by(reference=reference).first()
            
            if transaction and transaction.status == 'pending':
                transaction.status = 'completed'
                
                # Update user balance for deposits
                if transaction.transaction_type == 'deposit':
                    # Changed from lowercase 'user' to 'User'
                    current_user = User.query.get(transaction.user_id)
                    current_user.balance += transaction.amount
                    
                db.session.commit()
        
        return '', 200
    
    
    @app.route('/pay', methods=['POST'])
    def pay():
        # Changed from lowercase 'user' to 'User'
        current_user = User.query.get(session['user_id'])
        amount = float(request.form.get('amount'))
        
        # Initialize transaction
        response = initialize_transaction(current_user.email, amount, callback_url=url_for('verify_payment', _external=True))
        
        if response['status']:
            # Create a transaction record
            transaction = Transaction(
                amount=amount,
                transaction_type='deposit',
                reference=response['data']['reference'],
                user_id=current_user.id,
                status='pending'
            )
            db.session.add(transaction)
            db.session.commit()
            
            # Redirect to Paystack payment page
            return redirect(response['data']['authorization_url'])
        else:
            flash('Payment initialization failed', 'danger')
            return redirect(url_for('deposit'))
    
    return app

# Create the application instance
app = create_app()

if __name__ == '__main__':
    app.run(debug=True)