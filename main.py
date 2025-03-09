from functools import wraps
from flask import Flask, render_template, request, url_for, flash, redirect, abort, session
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy.orm import relationship
import smtplib
from email.message import EmailMessage
import os
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin,login_user,login_required, LoginManager, current_user,logout_user
from flask_ckeditor import CKEditor
from forms import CreateContactForm,CreatePostForm,CreateRegistrationForm,LoginForm,CreateCommentForm,CreateOtpForm
import bleach
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from random import randint


load_dotenv()

email_sender = os.environ.get("EMAIL")
email_receiver = os.environ.get("EMAIL_REC")
password_sender = os.environ.get("PASSWORD")

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET")
ckeditor = CKEditor(app)
Bootstrap(app)
csrf = CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["5 per minute"])



#Creating database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///blog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)  # Initialize Flask-Migrate



login_manager = LoginManager()
login_manager.init_app(app=app)
login_manager.login_view= "login"


def generate_otp():
    otp = randint(100000,999999)
    expiry_time = datetime.now() + timedelta(minutes=10)
    session["otp"] = str(otp)
    session['otp_expiry'] = expiry_time.strftime("%Y-%m-%d %H:%M:%S")
    return otp



@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(128), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    posts = relationship("Post", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")

    def __init__(self, email, password, name):
        self.email = email
        self.password = password
        self.name = name

class Post(db.Model):
    __tablename__ = "posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    comments = relationship("Comment", back_populates="parent_post")

allowed_tags = ['b', 'i', 'u', 'strong', 'em', 'p']
class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")
    comment_date = db.Column(db.String)
    post_id = db.Column(db.Integer, db.ForeignKey("posts.id"))
    parent_post= relationship("Post", back_populates="comments")
    text = db.Column(db.String, nullable=False)

    def set_text(self, raw_text):
        self.text = bleach.clean(raw_text, tags=allowed_tags)


with app.app_context():
    db.create_all()

import sqlite3

conn = sqlite3.connect("blog.db")
with open("dump.sql", "w") as file:
    for line in conn.iterdump():
        file.write(f"{line}\n")
conn.close()
print("Database dump created successfully!")

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        #If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        #Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function


@app.route("/")
def home():
    posts = Post.query.order_by(Post.id).all()
    return render_template("index.html",
                           heading="Daniel's Blog",
                           head_text="Collection of Daniel's Tech Update",
                           filename= "home-bg.jpg",
                           all_posts=posts,
                           logged_in=current_user.is_authenticated)

@app.route("/about")
def about():
    return render_template("about.html", heading="About Me",
                           head_text="This is what i do",
                           filename="about-bg2.jpg",
                           logged_in=current_user.is_authenticated)

@app.route("/contact")
def contact():
    form = CreateContactForm()
    return render_template("form.html", heading="Contact Me",
                           head_text="Have a question?/ I have answer",
                           filename= "contact-bg2.jpg",
                           logged_in=current_user.is_authenticated,
                           form=form,
                           form_type = "contact_form")

@app.route("/post/<int:post_id>", methods=["GET", "POST"])
@login_required
def show_post(post_id):
    requested_post = db.session.query(Post).filter(Post.id == post_id).first()
    form= CreateCommentForm()
    return render_template("post.html",
                           form=form,
                           post=requested_post,
                           logged_in=current_user.is_authenticated,
                           )

@app.route("/add_comment/<int:post_id>", methods=["GET", "POST"])
@limiter.limit("3 per minute")
def add_comment(post_id):
    requested_post = db.session.query(Post).filter(Post.id == post_id).first()
    if request.method == "POST":
        if not current_user.is_authenticated:
            flash("You need to login or register to comment")
            return redirect(url_for("login"))
        comment_text = request.form.get("comment_text")
        if len(comment_text) < 3:
            flash("Your comment is to short")
        else:
            new_comment = Comment(
                text= comment_text,
                comment_author=current_user,
                parent_post=requested_post,
                comment_date = datetime.today().strftime("%b %d, %Y"),
            )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for("show_post", post_id=post_id))

@app.route("/form-entry", methods=["post"])
@login_required
def receive_message():
    name = request.form["name"]
    email = request.form["email"]
    phone_num = request.form["phone_number"]
    message = request.form["message"]
    msg = EmailMessage()
    msg["From"] = email_sender
    msg["To"] = email_receiver
    msg["Subject"] = "Message from Blog viewer"
    msg.set_content(f"Name: {name}\n Email: {email}\n Phone number: {phone_num}\n Message: {message}")
    try:
        with smtplib.SMTP("smtp.mail.yahoo.com", 587) as connection:
            connection.ehlo()
            connection.starttls()
            connection.login(user=email_sender, password=password_sender)
            connection.send_message(msg)
        flash("Message sent successfully!")
        return redirect(url_for("contact"))
    except Exception as e:
        flash(f"An error occurred: {e}")
        return redirect(url_for("contact"))

@app.route("/new-post", methods=["GET", "POST"])
@login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = Post(
            title= request.form.get("title"),
            subtitle= request.form.get("subtitle"),
            body= request.form.get("body"),
            date=datetime.today().strftime("%B %d, %Y"),
            author_id=current_user.id,
            img_url=request.form.get("img_url"),
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("home"))
    return render_template("make-post.html",form=form,
                           is_edit=False,
                           logged_in=current_user.is_authenticated)

@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
@admin_only
def edit_post(post_id):
    post = db.session.query(Post).filter(Post.id == post_id).first()
    edit_form = CreatePostForm(
        title= post.title,
        subtitle=post.subtitle,
        author=post.author,
        body=post.body,
        img_url=post.img_url
    )
    if edit_form.validate_on_submit():
        post.title = request.form.get("title")
        post.subtitle = request.form.get("subtitle")
        post.author = request.form.get("author")
        post.body =request.form.get("body"),
        post.img_url = request.form.get("img_url")
        db.session.commit()
        return redirect(url_for("show_post", post_id=post_id))
    return render_template("make-post.html",
                           form=edit_form,
                           is_edit=True,
                           logged_in=current_user.is_authenticated)

@app.route("/delete/<int:post_id>", methods=["GET", "POST"])
@login_required
@admin_only
def delete_post(post_id):
    post = db.session.query(Post).filter(Post.id == post_id).first()
    if not post:
        flash("Post not found!")
        return redirect(url_for("home"))
    if request.method == "POST":
        db.session.delete(post)
        db.session.commit()
        return redirect(url_for("home"))

@app.route("/delete/<int:post_id>/<int:comment_id>", methods=["GET","POST"])
@login_required
def delete_comment(post_id,comment_id):
    comment = db.session.query(Comment).filter(Comment.id == comment_id).first()
    if not comment:
        flash("Comment not found!")
        return redirect(url_for("show_post", post_id=post_id ))
    db.session.delete(comment)
    db.session.commit()
    return redirect(url_for("show_post", post_id=post_id))


@app.route("/otp_authentication", methods=["GET","POST"])
def verify_otp():
    form=CreateOtpForm()
    if form.validate_on_submit():
        stored_otp = session.get("otp")
        expire_otp = session.get("otp_expiry")
        expiry_otp = datetime.strptime(expire_otp,"%Y-%m-%d %H:%M:%S")
        user_otp = request.form.get("otp")
        if stored_otp is None or not expire_otp:
            flash("OTP expired or missing. Please request a new one.")
            return redirect(url_for("register"))
        if not user_otp or not user_otp.isdigit():
            flash("Invalid OTP. Please enter a numeric value.")
            return redirect(url_for("verify_otp"))
        if datetime.now() > expiry_otp:
            session.pop("otp", None)
            session.pop("otp_expiry", None)
            flash("OTP has expired, please request a new one by entering your information again!")
            return redirect(url_for("register"))

        if stored_otp == str(user_otp):
            hash_and_salted_password = generate_password_hash(
                session.get("user_password"),
                method='pbkdf2:sha256',
                salt_length=8,
            )
            new_user = User(
                name=session.get("user_name"),
                password=hash_and_salted_password,
                email=session.get("user_email")
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for("home"))
        else:
            flash("You enter wrong otp, please try again!")
            return redirect(url_for("verify_otp"))
    return render_template("form.html", heading="Register",
                           head_text="Start contributing to the blog",
                           filename="register-bg.jpg",
                           is_contact = False,
                           logged_in=current_user.is_authenticated,
                           form=form,
                           form_type="otp")

@app.route("/register", methods=["GET","POST"])
def register():
    form = CreateRegistrationForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=request.form.get("email")).first():
            flash("You've already signed up with that email, login instead")
            return redirect(url_for("login"))
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")
        # send otp to check if the email is correct
        otp = generate_otp()
        msg = EmailMessage()
        msg["From"] = email_sender
        msg["To"] = email
        msg["Subject"] = "Daniel's blog OTP request"
        body = f"""{datetime.now().strftime('%B %d,%Y')}
                        
Hello {name}

You are receiving this email because a request was made for a one-time code that can be used for
authentication for Daniel's Blog account creation.

The one time verification code provided below is valid for 10 minutes.

please enter the following code for verification.


{otp}


please do not reply!
        
        """
        msg.set_content(body)
        try:
            with smtplib.SMTP("smtp.mail.yahoo.com", 587) as connection:
                connection.ehlo()
                connection.starttls()
                connection.login(user=email_sender, password=password_sender)
                connection.send_message(msg)
            flash("Message sent successfully!")
            return redirect(url_for("verify_otp", user_name= name, user_password = password, user_email=email))
        except Exception as e:
            flash(f"An error occurred: {e}")
            return redirect(url_for("register"))
    return render_template("form.html", heading="Register",
                           head_text="Start contributing to the blog",
                           filename="register-bg.jpg",
                           is_contact = False,
                           logged_in=current_user.is_authenticated,
                           form=form,
                           form_type="register")

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("The email doesn't exist please try again or sign up")
            return redirect(url_for("login"))
        elif not check_password_hash(user.password, password):
            flash("Password incorrect, please try again")
            return redirect(url_for("login"))
        else:
            login_user(user)
            return redirect(url_for("home"))

    return render_template("form.html", heading="Log In",
                           head_text="Welcome back!",
                           filename="login-bg.jpg",
                           is_contact=False,
                           is_register = False,
                           is_login = True,
                           logged_in=current_user.is_authenticated,
                           form=form,
                           form_type="login")

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

if __name__ == "__main__":
    app.run(debug=True)