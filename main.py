from functools import wraps
from flask import Flask, render_template, request, url_for, flash, redirect, abort
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
import smtplib
from email.message import EmailMessage
import os
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin,login_user,login_required, LoginManager, current_user,logout_user
from flask_ckeditor import CKEditor
from forms import CreateContactForm,CreatePostForm,CreateRegistrationForm,LoginForm,CreateCommentForm
import bleach


ALLOWED_TAGS = ["h1","h2","h3","h4","h5","h6","b","em","li","ul","ol","strong","p","sub","sup"]

email_sender = os.environ.get("EMAIL")
email_receiver = os.environ.get("EMAIL_REC")
password_sender = os.environ.get("PASSWORD")

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET")
ckeditor = CKEditor(app)
Bootstrap(app)


#Creating database
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///blog.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


login_manager = LoginManager()
login_manager.init_app(app=app)
login_manager.login_view= "login"


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


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")
    comment_date = db.Column(db.String)
    post_id = db.Column(db.Integer, db.ForeignKey("posts.id"))
    parent_post= relationship("Post", back_populates="comments")
    text = db.Column(db.String, nullable=False)


with app.app_context():
    db.create_all()

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
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment")
            return redirect(url_for("login"))
        new_comment = Comment(
            text= request.form.get("comment_text"),
            comment_author=current_user,
            parent_post=requested_post,
            comment_date = datetime.today().strftime("%b %d, %Y"),
        )
        db.session.add(new_comment)
        db.session.commit()
    return render_template("post.html",
                           form=form,
                           post=requested_post,
                           logged_in=current_user.is_authenticated,
                           comment_author=current_user.name,
                           )

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
        print("Message sent successfully!")
        return render_template("form.html", heading="Message sent successfully!",
                               head_text="Have a question?/ I have answer",
                               filename="contact-bg2.jpg",
                               is_contact=True,
                               logged_in=current_user.is_authenticated,
                               form=CreateContactForm(),
                               form_type="contact_form")
    except Exception as e:
        print(f"An error occurred: {e}")
        return render_template("form.html", heading="Unfortunately your message is not sent! please fill the form again!",
                           head_text="Have a question?/ I have answer",
                           filename= "contact-bg2.jpg",
                           is_contact=True,
                           logged_in=current_user.is_authenticated,
                           form=CreateContactForm(),
                           form_type = "contact_form")

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
        post.body = bleach.clean(request.form.get("body"), tags=ALLOWED_TAGS, attributes={})
        post.img_url = request.form.get("img_url")
        db.session.commit()
        return redirect(url_for("show_post", post_id=post_id))
    return render_template("make-post.html",
                           form=edit_form,
                           is_edit=True,
                           logged_in=current_user.is_authenticated)

@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    post = db.session.query(Post).filter(Post.id == post_id).first()
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for("home"))

@app.route("/register", methods=["GET","POST"])
def register():
    form = CreateRegistrationForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=request.form.get("email")).first():
            flash("You've already signed up with that email, login instead")
            return redirect(url_for("login"))
        hash_and_salted_password = generate_password_hash(
            request.form.get("password"),
            method='pbkdf2:sha256',
            salt_length=8,
        )
        new_user = User(
            name=request.form.get("name"),
            password=hash_and_salted_password,
            email=request.form.get("email")
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("home"))
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