import os
import random
import string
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, IntegerField
from wtforms.validators import DataRequired, Email, EqualTo
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(150), nullable=False)
    last_name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

class Restaurant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    address = db.Column(db.String(300), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    code = db.Column(db.String(10), unique=True, nullable=False)

class Vacancy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False)
    counter_seats = db.Column(db.Integer, nullable=False)
    table_seats = db.Column(db.Integer, nullable=False)
    private_rooms = db.Column(db.Integer, nullable=False)
    availability_time = db.Column(db.Integer, nullable=False)

class Menu(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False)
    details = db.Column(db.Text, nullable=False)

class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False)
    filename = db.Column(db.String(300), nullable=False)

class SignUpForm(FlaskForm):
    first_name = StringField('名', validators=[DataRequired()])
    last_name = StringField('姓', validators=[DataRequired()])
    email = StringField('メール', validators=[DataRequired(), Email()])
    password = PasswordField('パスワード', validators=[DataRequired()])
    confirm_password = PasswordField('パスワード確認', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('アカウント作成')

class LoginForm(FlaskForm):
    email = StringField('メール', validators=[DataRequired(), Email()])
    password = PasswordField('パスワード', validators=[DataRequired()])
    submit = SubmitField('ログイン')

class RestaurantSignUpForm(FlaskForm):
    name = StringField('店名', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    address = StringField('Address', validators=[DataRequired()])
    email = StringField('電話番号', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class VacancyForm(FlaskForm):
    counter_seats = IntegerField('Counter Seats', validators=[DataRequired()])
    table_seats = IntegerField('Table Seats', validators=[DataRequired()])
    private_rooms = IntegerField('Private Rooms', validators=[DataRequired()])
    availability_time = IntegerField('Availability Time', validators=[DataRequired()])
    submit = SubmitField('Add Vacancy')

def generate_unique_code(length=10):
    """Generate a unique code."""
    while True:
        code = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        existing_code = Restaurant.query.filter_by(code=code).first()
        if not existing_code:
            return code

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/choose_registration')
def choose_registration():
    return render_template('choose_registration.html')

@app.route('/signup_user', methods=['GET', 'POST'])
def signup_user():
    form = SignUpForm()
    error_message = None
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            error_message = 'すでに使用されているメールです'
            return render_template('signup_user.html', form=form, error_message=error_message)

        user = User(first_name=form.first_name.data, last_name=form.last_name.data,
                    email=form.email.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()

        session['user_email'] = form.email.data
        flash('アカウントが作成されました。{}!'.format(form.email.data), 'success')
        return redirect(url_for('index'))

    return render_template('signup_user.html', form=form, error_message=error_message)

@app.route('/signup_restaurant_owner', methods=['GET', 'POST'])
def signup_restaurant_owner():
    form = RestaurantSignUpForm()
    if form.validate_on_submit():
        code = generate_unique_code()
        restaurant = Restaurant(name=form.name.data, description=form.description.data,
                                address=form.address.data, email=form.email.data,
                                password=form.password.data, code=code)
        try:
            db.session.add(restaurant)
            db.session.commit()
            flash('Account created for {}!'.format(form.email.data), 'success')
            return redirect(url_for('login_restaurant_owner'))
        except Exception as e:
            db.session.rollback()
            flash('Error: {}'.format(str(e)), 'danger')
    return render_template('signup_restaurant_owner.html', form=form)

@app.route('/login_user', methods=['GET', 'POST'])
def login_user():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email, password=password).first()
        if user:
            session['user_email'] = email
            return redirect(url_for('index'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login_user.html', form=form)

@app.route('/login_restaurant_owner', methods=['GET', 'POST'])
def login_restaurant_owner():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        owner = Restaurant.query.filter_by(email=email, password=password).first()
        if owner:
            session['restaurant_owner_email'] = email
            return redirect(url_for('profile_restaurant'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login_restaurant_owner.html', form=form)

@app.route('/login_restaurant_staff', methods=['GET', 'POST'])
def login_restaurant_staff():
    form = LoginForm()
    if request.method == 'POST':
        code = request.form['code']
        restaurant = Restaurant.query.filter_by(code=code).first()
        if restaurant:
            session['restaurant_code'] = code
            return redirect(url_for('add_vacancy'))
        else:
            flash('Invalid Code. Please try again.', 'danger')
    return render_template('login_restaurant_staff.html', form=form)

@app.route('/profile_restaurant', methods=['GET', 'POST'])
def profile_restaurant():
    # Add necessary form if any for this page
    form = None
    return render_template('profile_restaurant.html', form=form)

@app.route('/add_vacancy', methods=['GET', 'POST'])
def add_vacancy():
    if 'restaurant_code' not in session:
        flash('You need to log in first', 'warning')
        print("Access to add_vacancy denied. No restaurant_code in session")
        return redirect(url_for('login_restaurant_staff'))
    
    form = VacancyForm()
    if form.validate_on_submit():
        restaurant_code = session.get('restaurant_code')
        restaurant = Restaurant.query.filter_by(code=restaurant_code).first()
        if restaurant:
            vacancy = Vacancy(
                restaurant_id=restaurant.id,
                counter_seats=form.counter_seats.data,
                table_seats=form.table_seats.data,
                private_rooms=form.private_rooms.data,
                availability_time=form.availability_time.data
            )
            db.session.add(vacancy)
            db.session.commit()
            flash('Vacancy added successfully!', 'success')
            return redirect(url_for('profile_restaurant'))
    return render_template('add_vacancy.html', form=form)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
