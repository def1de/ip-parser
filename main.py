import requests
from flask import Flask, redirect, render_template, url_for, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, current_user, login_required, login_user, logout_user
#<============== INIT ==============>

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ip-info.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = '0123456789'

db = SQLAlchemy(app)
login = LoginManager(app)

#<========== NO SITE FUNC ==========>

def ip_info(ip):
    for i in Ip.query.all():
        if ip == i.ip: return True

    try:
        response = requests.get(url=f'http://ipwhois.app/json/{ip}').json()
        db.session.add(Ip(ip = response.get('ip'), country = response.get('country'), region = response.get('region'), city = response.get('city'), lat = response.get('latitude'), lon = response.get('longitude')))
        db.session.commit()
        return True

    except: return 'Exception'
#<============== TABLES ==============>

class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(20))
    password = db.Column(db.String(20))

class Ip(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(255), default="-")
    country = db.Column(db.String(255), default="-")
    region = db.Column(db.String(255), default="-")
    city = db.Column(db.String(255), default="-")
    lat = db.Column(db.String(255), default="-")
    lon = db.Column(db.String(255), default="-")

#<============== ADMIN-CLASSES ==============>

@login.user_loader
def load_user(user_id):
    return Users.query.get(user_id)

#<============== PAGES ==============>

@app.route('/')
def index():
    ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    a = ip_info(ip=ip)
    if a == True: return render_template('index.html', ip = ip)
    else: return a

@app.route('/login', methods=["GET", "POST"])
def log_in():
    if request.method == "POST":
        login = request.form['login']
        password = request.form['password']

        for i in Users.query.all():
            if login == i.login:
                if password == i.password:
                    login_user(i)
                    return redirect('/ip')
        return redirect('/login')

    else: return render_template('login.html')

@app.route('/ip')
@login_required
def view_ip():
    return render_template('ip.html', data = Ip.query.order_by(Ip.id.desc()).all())

@app.route('/ip/<int:id>/delete')
@login_required
def data_admins_delete(id):
    try:
        db.session.delete(Ip.query.get_or_404(id))
        db.session.commit()
        return redirect('/ip')
    except: return "<h1>Error</h1>"

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/')

@app.errorhandler(404)
def page_not_found(error):
    return '<h1>Error 404</h1>'

@app.errorhandler(401)
def page_not_found(error):
    return redirect('/login')

if __name__ == "__main__":
    app.run(debug=True)