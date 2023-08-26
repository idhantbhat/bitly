from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from helpers import *
from flask_login import LoginManager, current_user, login_user, logout_user,UserMixin, login_required
from functools import wraps
from datetime import datetime, timedelta
from flask import abort
from dotenv import load_dotenv
import os

load_dotenv()
SECRET_KEY_ENV = os.getenv("SECRET_KEY_ENV")
SQLALCHEMY_DATABASE_URI = os.getenv("SQLALCHEMY_DATABASE_URI")


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = f'{SQLALCHEMY_DATABASE_URI}'
app.config['SECRET_KEY'] = f'{SECRET_KEY_ENV}'

db = SQLAlchemy(app)
Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)

# Set the login view for Flask-Login
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

    def get_id(self):
        return str(self.user_id)

class URL(db.Model):
    __tablename__ = 'urls'
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String, unique=True)
    shorturl = db.Column(db.String, unique=True)
    email = db.Column(db.String)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/", methods=["GET", "POST"])
def home():
    form = URLForm()
    if current_user.is_authenticated:
        if form.validate_on_submit():
            new_url = URL(
                url=form.url.data,
                shorturl=generate_random_string(),
                email=current_user.email
            )
            db.session.add(new_url)
            db.session.commit()
            return render_template("success.html", new_url=new_url)
        return render_template("index.html", form=form)
    else:
        return render_template("index.html", form=form, loggedout=True)

@app.route("/url/<shorturl>", methods=["GET"])
def redirect_url(shorturl):
    matching_url = URL.query.filter_by(shorturl=shorturl).first()

    if matching_url:
        original_url = matching_url.url
        if not (original_url.startswith("http://") or original_url.startswith("https://")):
            original_url = "https://" + original_url
        return redirect(original_url)
    else:
        return ("404 :/")




@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        confirm_password = form.confirm_password.data
        if User.query.filter_by(email=email).first():
            flash('Email address already registered.')
            return redirect(url_for('register'))
        if password != confirm_password:
            flash('Passwords do not match.')
            return redirect(url_for('register'))
        new_user = User(
            email=email,
            password=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful.')
        login_user(new_user)
        return redirect(url_for('home'))
    elif request.method == 'POST':
        if not form.email.data:
            flash('Please enter an email address.', 'error')
        elif not form.password.data:
            flash('Please enter a password.', 'error')
        else:
            flash('Account not created. Please check your input and try again.', 'error')
    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('home'))
            else:
                flash('Incorrect password.')
        else:
            flash('Email not registered.')
    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)