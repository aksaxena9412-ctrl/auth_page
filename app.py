from flask import Flask, render_template, request, redirect, session,flash
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import os

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(100), nullable = False)
    email = db.Column(db.String(100), unique = True)
    password = db.Column(db.String(100))
    
    def __init__(self, name, email, password):
        self.name = name
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'),self.password.encode('utf-8'))

with app.app_context():
    db.create_all()
    
    
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=['GET','POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        if not name:
            flash("Name cannot be empty.", "error")
            return redirect('/register')

        # Validation 2: Email should not be empty
        if not email:
            flash("Email cannot be empty.", "error")
            return redirect('/register')

        # Validation 3: Password should not be empty
        if not password:
            flash("Password cannot be empty.", "error")
            return redirect('/register')

        # Validation 4: Password must be at least 6 characters
        if len(password) < 6:
            flash("Password must be at least 6 characters long.", "error")
            return redirect('/register')

        # Validation 5: Email must be unique
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email already registered. Please use another email.", "error")
            return redirect('/register')
        
        new_user = User(name=name, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/login')
    
    return render_template("register.html")

@app.route("/login", methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        # Validation 1: Email empty
        if not email:
            flash("Email cannot be empty.", "error")
            return redirect('/login')

        # Validation 2: Password empty
        if not password:
            flash("Password cannot be empty.", "error")
            return redirect('/login')

        # Check if user exists
        user = User.query.filter_by(email=email).first()

        if not user:
            flash("Email is not registered.", "error")
            return redirect('/login')

        # Check password
        if not user.check_password(password):
            flash("Invalid password.", "error")
            return redirect('/login')

        # Login successful
        session['email'] = user.email
        flash("Login successful!", "success")
        return redirect('/dashboard')

    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if 'email' in session:
        user = User.query.filter_by(email=session['email']).first()
        return render_template("dashboard.html", user=user)
    return redirect('/login')

@app.route('/logout')
def logout():
    session.pop('email',None)
    return redirect('/login') 



if __name__ == '__main__':
    app.run()