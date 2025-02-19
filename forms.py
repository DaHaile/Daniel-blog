from flask_wtf import FlaskForm
from flask_ckeditor import CKEditorField
from wtforms.validators import InputRequired, Email, Length, Regexp, URL
from wtforms.fields.simple import StringField,SubmitField,EmailField,PasswordField,TextAreaField


class CreatePostForm(FlaskForm):
    title = StringField("Blog post title", validators=[InputRequired("Please enter a title")])
    subtitle= StringField("Blog subtitle", validators=[InputRequired("Please enter a subtitle")])
    author = StringField("Your name", validators=[InputRequired("Please enter the name of the author")])
    img_url = StringField("Blog image url", validators=[InputRequired("Please enter image url"),URL()])
    body = CKEditorField("Blog content", validators=[InputRequired("Please write the content")])
    submit= SubmitField("Submit Post")


class CreateRegistrationForm(FlaskForm):
    email= EmailField("Email", validators=[InputRequired("Please enter your email address"),Email("Please use a valid email address")])
    name = StringField("Name", validators=[InputRequired("Please enter your name")])
    password = PasswordField("Password", validators=[InputRequired("Please enter a password")])
    submit = SubmitField("SIGN ME UP")


class CreateContactForm(FlaskForm):
    name = StringField("Name", validators=[InputRequired("Please enter your name")])
    email= EmailField("Email", validators=[InputRequired("Please enter your email address"),Email("Please use a valid email address")])
    phone_number = StringField("Phone Number", validators=[Regexp(r'^\+?[1-9]\d{1,14}$', message="Invalid phone number format"),
            Length(min=10, max=15)])
    message = TextAreaField("Message", validators=[InputRequired("Please write your message")])
    submit = SubmitField("Send a Message")


class LoginForm(FlaskForm):
    email= EmailField("Email", validators=[InputRequired("Please enter your email address"),Email("Please use a valid email address")])
    password = PasswordField("Password", validators=[InputRequired("Please enter a password")])
    submit = SubmitField("Login")

class CreateCommentForm(FlaskForm):
    comment_text = CKEditorField("Comment", validators=[InputRequired("Please enter your comment!")])
    submit = SubmitField("Submit Comment")