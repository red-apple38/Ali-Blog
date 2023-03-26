from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from urllib.parse import urlparse, urljoin
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from functools import wraps
from flask_gravatar import Gravatar
import os


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
ckeditor = CKEditor(app)
Bootstrap(app)

# CONNECT TO DB

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
# postgres://blog_db_fixl_user:LAIJWzsliMcAQYXMdrd0d6I0d33RGGwR@dpg-cgg67iceoogqfc08jsog-a.frankfurt-postgres.render.com/blog_db_fixl
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Flask login
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = db.relationship('Comment', back_populates='related_blog')


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    posts = db.relationship('BlogPost', back_populates='author')
    comments = db.relationship('Comment', back_populates='comment_author')


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    comment_author = relationship('User', back_populates='comments')
    blog_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    related_blog = relationship('BlogPost', back_populates='comments')
    comment = db.Column(db.Text, nullable=False)

with app.app_context():
    db.create_all()


# safe_url
def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc


# admin
def admin(gate):
    @wraps(gate)
    def wrapper(*args,**kwargs):
        if current_user.id != 1:
            return abort(403, description='Access denied')
        else:
            return gate(*args, **kwargs)
    return wrapper


# Gravatar profile pic
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)




@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['GET','POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        password = form.password.data
        hashed_password = generate_password_hash(password,method='pbkdf2:sha256', salt_length=8)
        try:
            user = User(
                username=form.username.data,
                email=form.email.data,
                password=hashed_password
            )
            db.session.add(user)
            db.session.commit()
            login_user(user)

        except:
            db.session.rollback()
            flash('This email is already registered', "info")
            return redirect(url_for('login'))

        else:
            return redirect(url_for('get_all_posts'))

    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        try:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                next = request.args.get('next')
                if not is_safe_url(next):
                    return abort(400)
                return redirect(next or url_for('get_all_posts'))

            else:
                flash('Wrong Password - Try Again', 'info')
        except AttributeError:
            flash("This User does not exist!")

    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    comments = Comment.query.all()
    print(comments)
    if current_user.is_authenticated and form.validate_on_submit():
        comment = Comment(
            comment=form.comment.data,
            comment_author=current_user,
            related_blog=requested_post
        )
        db.session.add(comment)
        db.session.commit()

    elif not current_user.is_authenticated and form.validate_on_submit():
        flash('You need to be logged in to post a comment', 'info')

    return render_template("post.html", post=requested_post, form=form, comments=comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
@admin
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
