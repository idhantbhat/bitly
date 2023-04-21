from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField
from wtforms.validators import DataRequired, EqualTo, Length
import random
import string

class RegistrationForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=20)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')
class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=20)])
    submit = SubmitField('LOGIN')
class URLForm(FlaskForm):
    url = StringField('URl', validators=[DataRequired()])
    submit = SubmitField("Enter")

def generate_random_string():
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for i in range(7))
