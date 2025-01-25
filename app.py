
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os

app = Flask(__name__)

# Konfigurasi
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(basedir, 'database.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your_secret_key'

# Inisialisasi database dan modul tambahan
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # 'admin' atau 'user'

class Pesanan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nama = db.Column(db.String(100))
    email = db.Column(db.String(100))
    tanggal = db.Column(db.String(100))
    jumlah = db.Column(db.Integer)
    produk = db.Column(db.String(100))
    harga = db.Column(db.Float)
    total_harga = db.Column(db.Float)
    pesan = db.Column(db.String(200))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



@app.route("/")
@login_required
def home():
    if current_user.role == "admin":
        message = "Selamat datang di Dashboard Admin!"
    else:
        message = "Selamat datang di Halaman Pembeli!"

    return render_template("index.html", message=message)

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.route("/menu")
def menu():
    return render_template("menu.html")

@app.route("/testimonial")
def testimonial():
    orders = Pesanan.query.all()
    return render_template("testimonial.html", orders=orders)

@app.route("/service")
def service():
    return render_template("service.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            # Redirect ke index dengan role tertentu
            if user.role == "admin":
                flash("Selamat datang, Admin!", "success")
            else:
                flash("Selamat datang, Pembeli!", "success")
            return redirect(url_for("home"))
        else:
            flash("Login gagal. Periksa username dan password.", "danger")
    return render_template("login.html")

@app.route("/admin")
@login_required
def admin_dashboard():
    if current_user.role != "admin":
        return redirect(url_for("home"))
    return render_template("admin_dashboard.html")

@app.route("/user")
@login_required
def user_dashboard():
    if current_user.role != "user":
        return redirect(url_for("home"))
    return render_template("user_dashboard.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/reservation", methods=["GET", "POST"])
def reservation():
    if request.method == "POST":
        nama = request.form["nama"]
        email = request.form["email"]
        tanggal = request.form["tanggal"]
        jumlah = int(request.form["jumlah"])
        produk = request.form["produk"]
        harga = float(request.form["harga"])
        total_harga = float(request.form["Totalharga"])
        pesan = request.form.get("pesan", "")

        pesanan_baru = Pesanan(
            nama=nama,
            email=email,
            tanggal=tanggal,
            jumlah=jumlah,
            produk=produk,
            harga=harga,
            total_harga=total_harga,
            pesan=pesan,
        )
        db.session.add(pesanan_baru)
        db.session.commit()
        return redirect(url_for("home"))
    return render_template("reservation.html")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()

     # Tambahkan admin jika belum ada
        if not User.query.filter_by(username="admin").first():
            hashed_password = bcrypt.generate_password_hash("admin123").decode("utf-8")
            admin_user = User(username="admin", password=hashed_password, role="admin")
            db.session.add(admin_user)

        # Tambahkan pembeli (user) jika belum ada
        if not User.query.filter_by(username="pembeli").first():
            hashed_password = bcrypt.generate_password_hash("pembeli123").decode("utf-8")
            buyer_user = User(username="pembeli", password=hashed_password, role="user")
            db.session.add(buyer_user)

        db.session.commit()

    app.run(debug=True)



