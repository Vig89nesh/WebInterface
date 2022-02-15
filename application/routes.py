from application import app
from flask import flash,render_template,url_for,redirect,request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin,login_user,LoginManager,login_required,logout_user,current_user
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField,TextAreaField
from wtforms.validators import InputRequired,length,ValidationError
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO

socketio = SocketIO(app, cors_allowed_orgins="*")
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view="login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
class User(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20),nullable=False,unique=True)
    password = db.Column(db.String(80),nullable=False)

class AddUsers(FlaskForm):
    username = StringField(validators=[InputRequired(), length(min=4, max=20)], render_kw={"placeholder":"Username"})
    password = PasswordField(validators=[InputRequired(), length(min=4, max=20)], render_kw={"palceholder":"Password"})
    submit = SubmitField("Create")

class Delete(FlaskForm):
    username = StringField(validators=[InputRequired(),length(min=4, max=20)],render_kw={"placeholder": "Enter  username to delete"})
    submit = SubmitField("Delete")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(),length(min=4,max=20)],render_kw={"placeholder":"Username"})
    password = PasswordField(validators=[InputRequired(),length(min=4,max=20)],render_kw={"placeholder":"Password"})
    submit = SubmitField("Login")

@app.route("/")

def index():
    return render_template("index.html")

@app.route("/login", methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if user.username != 'groupadmin':
                if bcrypt.check_password_hash(user.password,form.password.data):
                    login_user(user)
                    return redirect(url_for('session'))
                else:
                    flash("Password Invalid!!")
            else:
                if bcrypt.check_password_hash(user.password,form.password.data):
                    login_user(user)
                    return redirect(url_for('admin'))
                else:
                    flash("Password Invalid")
        else:
            flash("Invalid username or password")

    return render_template("login.html",form=form)
@app.route("/admin")
@login_required
def admin():
    return render_template('Admin.html')
@app.route("/addUsers",methods=['GET','POST'])
@login_required
def addUsers():
    form = AddUsers()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if not user:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            new_user = User(username=form.username.data, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash("User added Successfully")
            return redirect(url_for('addUsers'))
        else:
            flash("User already exists...")

    return render_template("AddUsers.html",form=form)

@app.route("/DeleteUsers", methods=['GET','POST'])
@login_required
def DeleteUsers():
    form = Delete()
    if form.validate_on_submit():
        user= User.query.filter_by(username=form.username.data).first()
        if user:
            User.query.filter_by(id=user.id).delete()
            db.session.commit()
            flash("User Deleted Successfully!!")
            return redirect(url_for('DeleteUsers'))
        else:
            flash("User does not exists")

    return render_template("DeleteUser.html",form=form)
@app.route('/rest/addusers',methods=['GET','POST'])
def addUsers_api():
    if 'username' in request.args:
        username = request.args['username']
        if 'password' in request.args:
            password = request.args['password']
            user =  User.query.filter_by(username=username).first()
            if not user:
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                new_user = User(username=username,password=hashed_password)
                db.session.add(new_user)
                db.session.commit()

                return {"Status": "Success", "message":"User Added Successfully"}
            else:
                return {"Status": "Warning", "message":"User already exists"}
        else:
            return {"Status": "Error", "message":"Password field not present"}
    else:
        return {"Status": "Error", "message": "No username field provided"}
@app.route('/rest/deleteusers', methods=['GET','POST'])
def DeleteUsers_api():
    if 'username' in request.args:
        username = request.args['username']
        user = User.query.filter_by(username=username).first()
        if user:
            User.query.filter_by(id=user.id).delete()
            db.session.commit()
            return {"Status":"Success","message":"User deleted!!!"}
        else:
            return {"Status":"Warning","message":"User does not exists"}

    else:
        return{"Status":"Error", "message":"Username field not provided"}

@app.route("/session",methods=['GET','POST'])
@login_required
def session():
    return render_template('session.html',user=current_user.username)
def messageReceived(methods=['GET','POST']):
    print('Message was received...')

@socketio.on('my event')
def handle_my_custom_event(json,methods=['GET','POST']):
    print('Event received: ' +str(json))
    socketio.emit('my response', json, callback=messageReceived)