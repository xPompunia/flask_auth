from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['SECRET_KEY'] = 'secret-key-goes-here'



# CREATE DATABASE
class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# CREATE TABLE IN DB
class User(db.Model, UserMixin):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))


with app.app_context():
    db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == "POST":
        email = request.form.get('email')
        if db.session.execute(db.select(User).where(User.email == email)).scalar():
            flash("You've already registered with that email, log in instead!")
            return redirect(url_for('login'))
        else:
            password = generate_password_hash(request.form.get('password'), method='pbkdf2:sha256', salt_length=8)
            name = request.form.get('name')
            user = User(email=email, password=password, name=name)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            session['logged_in'] = True
            return redirect(url_for('secrets'))
    return render_template("register.html")




@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()
        # user = db.get_or_404(User, email)
        if user:
            if check_password_hash(user.password, request.form.get('password')):
                login_user(user)
                session['logged_in'] = True
                return redirect(url_for('secrets'))
            else:
                flash('Invalid password')
        else:
            flash('User does not exist')
            # return "Invalid credentials"
    return render_template("login.html", logged_in=current_user.is_authenticated)


@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html", name=current_user.name, logged_in=True)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    return send_from_directory(
        app.static_folder, 'files/cheat_sheet.pdf'
    )


if __name__ == "__main__":
    app.run(debug=True)
