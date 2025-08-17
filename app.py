from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from twilio.rest import Client
import random
import requests

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'gmjithendra111@gmail.com'  # Replace
app.config['MAIL_PASSWORD'] = 'pqls djkv taib pcwa'        # Replace
mail = Mail(app)

# Twilio configuration
TWILIO_ACCOUNT_SID = 'your_account_sid'
TWILIO_AUTH_TOKEN = 'your_auth_token'
TWILIO_PHONE_NUMBER = '7993133714'
client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    mobile = db.Column(db.String(15))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))
    is_admin = db.Column(db.Boolean, default=False)

# Get IP-based location
def get_location(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}").json()
        return f"{res.get('city')}, {res.get('regionName')}, {res.get('country')}"
    except:
        return "Unknown"

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        mobile = request.form['mobile']
        email = request.form['email']
        password = request.form['password']
        action = request.form['action']

        session['signup_form'] = {'name': name, 'mobile': mobile, 'email': email, 'password': password}

        if action == 'send_otp':
            if User.query.filter_by(email=email).first():
                return render_template('signup.html', error="Email already exists.", **session['signup_form'])

            otp = str(random.randint(100000, 999999))
            session['otp'] = otp

            # Send Email OTP
            msg = Message(
                subject='Your OTP Verification - YSRCP',
                sender=('YSRCP Help', app.config['MAIL_USERNAME']),
                recipients=[email]
            )
            msg.body = f"""
            Dear User,

            Thank you for registering with YSRCP Team.
            Your One-Time Password (OTP) is: {otp}

            Regards,
            YSRCP Team
            """
            mail.send(msg)

            # Send SMS OTP
            try:
                client.messages.create(
                    to=f"+91{mobile}",
                    from_=TWILIO_PHONE_NUMBER,
                    body=f"Your YSRCP OTP is: {otp}"
                )
            except Exception as e:
                print("SMS sending failed:", e)

            return render_template('signup.html', otp_sent=True, **session['signup_form'])

        elif action == 'verify_otp':
            if request.form['otp'] == session.get('otp'):
                data = session.get('signup_form')
                if not data:
                    return redirect(url_for('signup'))

                hashed_pw = generate_password_hash(data['password'])
                new_user = User(name=data['name'], mobile=data['mobile'], email=data['email'], password=hashed_pw)
                db.session.add(new_user)
                db.session.commit()

                session.pop('otp', None)
                session.pop('signup_form', None)
                return redirect(url_for('login'))
            else:
                return render_template('signup.html', error="Invalid OTP", otp_sent=True, **session['signup_form'])

    return render_template('signup.html', otp_sent=False, name='', mobile='', email='')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email_or_mobile = request.form['email_mobile']
        password = request.form['password']

        user = User.query.filter(
            (User.email == email_or_mobile) | (User.mobile == email_or_mobile)
        ).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.name
            ip = request.remote_addr
            location = get_location(ip)
            print(f"User: {user.name} | IP: {ip} | Location: {location}")

            return redirect(url_for('dashboard'))

        return render_template('login.html', error="Invalid credentials")

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if user.is_admin:
        return render_template('admin_dashboard.html', username=user.name)
    return render_template('dashboard.html', username=user.name)

@app.route("/reports")
def reports():
    return render_template("reports.html")

@app.route("/announcements")
def announcements():
    return render_template("announcements.html")

@app.route("/manage_users")
def manage_users():
    return render_template("manage_users.html")

@app.route("/location_updates")
def location_updates():
    return render_template("location_updates.html")

@app.route("/settings")
def settings():
    return render_template("settings.html")

@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()   # clear all session data
    return redirect(url_for("login"))

# Create DB and run
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
