import os
from datetime import datetime, timedelta
from flask import Flask, render_template,  redirect, url_for, flash, request, current_app, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, current_user, logout_user, login_user, login_required
from flask_bcrypt import Bcrypt
import secrets
from PIL import Image
from flask_mail import Mail
from itsdangerous.url_safe import URLSafeTimedSerializer as Serializer
from werkzeug.utils import secure_filename
import forms
import jwt

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)

SECRET_KEY = os.urandom(32)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = ('sqlite:///'+ os.path.join(basedir, 'notes.sqlite')) + '?check_same_thread=False'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = r'C:\Users\Dell\Downloads\Monika_kursai\Baigiamasis\static\note_pics'
db = SQLAlchemy(app)

bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

class User(db.Model, UserMixin):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(60), nullable=False)
    notes = db.relationship('Note', backref='author', lazy=True)
    
    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.image_file}')"
    
    def get_reset_token(self, expires_sec=18000):
        payload = {
            'user_id': self.id,
            'exp': datetime.utcnow() + timedelta(seconds=expires_sec)
        }
        token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
        return token
    
    @staticmethod
    def verify_reset_token(token):
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user_id = payload['user_id']
        except:
            return None
        return User.query.get(user_id)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Note(db.Model):
    __tablename__ = "note"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    note_picture = db.Column(db.String(20), nullable=True)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey("category.id"), nullable=True)
    category = db.relationship("Category")

class Category(db.Model):
    __tablename__ = "category"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column('Title', db.String(50), nullable=False)
    notes = db.relationship('Note')

app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASSWORD')
mail = Mail(app)

@app.route("/register", methods=['GET', 'POST'])
def register():
    db.create_all()
    if current_user.is_authenticated:
        return redirect(url_for('profile'))
    form = forms.RegistrationForm()
    if form.validate_on_submit():
        bcrypt_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, email=form.email.data, password=bcrypt_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created!', 'success')
        return redirect(url_for('profile'))
    return render_template('register.html', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('notes'))
    form = forms.LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('notes'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', title='Login', form=form)

def send_reset_email(user):
    token = user.get_reset_token()
    print(url_for('reset_token', token=token, _external=True))
    
@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('notes'))
    form = forms.RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('Please check an email', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Password', form=form)

@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('notes'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('Link has expired', 'warning')
        return redirect(url_for('reset_request'))
    form = forms.PasswordResetForm()
    if form.validate_on_submit():
        encode = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = encode
        db.session.commit()
        flash('Your password has been updated! Please log in', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('base'))

def reset_email(user):
    token = user.get_reset_token()
    print(url_for('reset_token', token=token, _external=True))

def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)

    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)

    return picture_fn

@app.route("/profile", methods=['GET', 'POST'])
@login_required
def profile():
    form = forms.ProfileEditForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template('profile.html', title='Account', form=form, image_file=image_file)


@app.route("/note/new", methods=['GET', 'POST'])
@login_required
def new_note():
    form = forms.NoteForm()
    if form.validate_on_submit():
        if form.note_picture.data:
            picture_file = form.note_picture.data
            picture_filename = secure_filename(picture_file.filename)
            picture_path = os.path.join(current_app.config['UPLOAD_FOLDER'], picture_filename)
            picture_file.save(picture_path)
            note_picture = picture_filename
        else:
            note_picture = None
        note = Note(title=form.title.data, content=form.content.data, author=current_user, note_picture=note_picture)
        db.session.add(note)
        db.session.commit()
        flash('Your note has been created!', 'success')
        return redirect(url_for('notes'))
    note_picture = None
    if note_picture:
        note_picture = url_for('static', filename='note_pics/' + note_picture)
    return render_template('add_note.html', title='New Note', note_picture=note_picture,
                           form=form, legend='New Note')

@app.route("/note/<int:note_id>")
@login_required
def note(note_id):
    note = Note.query.get_or_404(note_id)
    return render_template('note.html', title=note.title, note=note)

@app.route("/category/<int:category_id>")
@login_required
def category(category_id):
    category = Category.query.get_or_404(category_id)
    return render_template('category.html', title=category.title, category=category)

@app.route("/note/<int:note_id>/update", methods=['GET', 'POST'])
@login_required
def update_note(note_id):
    note = Note.query.get_or_404(note_id)
    if note.author != current_user:
        abort(403)
    form = forms.NoteForm()
    if form.validate_on_submit():
        if form.note_picture.data:
            picture_file = form.note_picture.data
            picture_filename = secure_filename(picture_file.filename)
            picture_path = os.path.join(current_app.config['UPLOAD_FOLDER'], picture_filename)
            picture_file.save(picture_path)
            note.note_picture = picture_filename
        note.title = form.title.data
        note.content = form.content.data
        if form.category.data:
            note.category_id = form.category.data.id
        else:
            note.category_id = None 
        db.session.commit()
        flash('Your note has been updated!', 'success')
        return redirect(url_for('note', note_id=note.id))
    elif request.method == 'GET':
        form.title.data = note.title
        form.content.data = note.content
        if note.category is not None:
            form.category.data = note.category.title
    return render_template('add_note.html', title='Update Note',
                           form=form, legend='Update Note')
    
@app.route("/note/<int:note_id>/delete", methods=['POST'])
@login_required
def delete_note(note_id):
    note = Note.query.get_or_404(note_id)
    if note.author != current_user:
        abort(403)
    db.session.delete(note)
    db.session.commit()
    flash('Your note has been deleted!', 'success')
    return redirect(url_for('notes'))

@app.route("/notes", methods=['GET','POST'])
@login_required
def notes():
    q = request.args.get('q')
    if q:
        notes = Note.query.filter(Note.title.contains(q))
    else:
        notes = Note.query.all()
    return render_template('notes.html', notes=notes)

@app.route("/add_category", methods=["GET", "POST"])
@login_required
def add_category():
    form = forms.CategoryForm()
    if form.validate_on_submit():
        add_category = Category(title=form.title.data)
        db.session.add(add_category)
        db.session.commit()
        flash('Your category has been created!', 'success')
        return redirect(url_for('categories'))
    return render_template("add_category.html", form=form)

@app.route("/category/<int:category_id>/update", methods=['GET', 'POST'])
@login_required
def update_category(category_id):
    category = Category.query.get_or_404(category_id)
    form = forms.CategoryForm()
    if form.validate_on_submit():
        category.title = form.title.data
        db.session.commit()
        flash('Your category has been updated!', 'success')
        return redirect(url_for('categories', actegory_id=category.id))
    elif request.method == 'GET':
        form.title.data = category.title
    return render_template('add_category.html', title='Update Category',
                           form=form, legend='Update Category')

@app.route("/category_delete/<int:id>")
@login_required
def delete_category(id):
    category = Category.query.get_or_404(id)
    db.session.delete(category)
    db.session.commit()
    flash('Your category has been deleted!', 'success')
    return redirect(url_for('categories'))

@app.route("/categories", methods=['GET','POST'])
@login_required
def categories():
    try:
        categories = Category.query.all()
    except:
        categories = []
    print(categories)
    return render_template("categories.html", categories=categories)

@app.route("/")
@app.route("/home")
def base():
    return render_template('home.html')

if __name__ == '__main__':
    app.run(host='localhost', port=5001, debug=True)
    db.create_all()