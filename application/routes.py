from application import app
from flask import flash,render_template,url_for,redirect,request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin,login_user,LoginManager,login_required,logout_user,current_user
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField,TextAreaField,SelectField,SelectMultipleField
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

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    groupname = db.Column(db.String(80), nullable=False, unique=True)
    owner = db.Column(db.String(80), nullable=False)
class GroupUsers(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(80), db.ForeignKey(User.username,ondelete='CASCADE'))
    groupname = db.Column(db.String(80), db.ForeignKey(User.username,ondelete='CASCADE'))


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

class add_participant(FlaskForm):
    user = SelectField(validators=[InputRequired()], label='username', choices='',default=None)
    submit = SubmitField("Add")

class remove_participant(FlaskForm):
    user = SelectMultipleField(validators=[InputRequired()],label='username', choices='', default=None)
    submit = SubmitField("Remove")

class CreateGroup(FlaskForm):
    groupname = StringField(validators=[InputRequired(), length(min=4, max=30)], render_kw={"placeholder":"Enter GroupName"})
    submit = SubmitField("Create")

class DeleteGroup(FlaskForm):
    groupname = SelectMultipleField(validators=[InputRequired()], label='GroupName', choices='', default=None)
    submit = SubmitField("Delete")

@app.route("/")
def home():
    return redirect(url_for('login'))
@app.route("/login", methods=['POST','GET'])
def login():
    form = LoginForm()
    if form.validate_on_submit():

        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password,form.password.data):
                login_user(user)
                return redirect(url_for('manage_users'))
            else:
                flash("Password Invalid!!")
        else:
            flash("Invalid username or password")

    return render_template("login.html",form=form)

@login_required
@app.route("/manage", methods=['GET','POST'])
def manage_users():
    groups = Group.query.all()
    users = User.query.all()
    grp_user = GroupUsers.query.filter_by(user_name=current_user.username).all()
    return render_template('Manage.html',group=groups, user= users, group_user=grp_user)

@app.route('/addparticipant',methods=['POST','GET'])
@login_required
def add_participant():
    if "groupname" in request.args:
        grp_name = request.args["groupname"]

        form = add_participant()
        form.user.choices = [None] + [users.username for users in User.query.all()]

        if form.validate_on_submit():
            name = form.user.data
            grp_user = GroupUsers.query.filter_by(groupname=grp_name).all()
            grp_user = [g_user for g_user in grp_user if g_user.user_name.lower() == name.lower()]
            if not grp_user:
                new_member = GroupUsers(user_name=name,groupname = grp_name)
                db.session.add(new_member)
                db.session.commit()
                return "User Added into group!!!"
            else:
                return "User already exists!!!"
    return render_template("AddParticipant.html",form=form)
@app.route("/removeparticipant", methods=['GET','POST'])
@login_required
def remove():
    form = remove_participant()

    if 'groupname' in request.args:
        grpname = request.args['groupname']

        user_to_remove = [g_user.user_name for g_user in GroupUsers.query.filter_by(groupname=grpname).all()]
        form.user.choices = user_to_remove
        if form.validate_on_submit():
            if user_to_remove:
                selected_user = form.user.data
                [GroupUsers.query.filter_by(user_name=user, groupname = grpname).delete() for user in selected_user]
                db.session.commit()
                return "User removed successfully"
                time.sleep(5)
                return redirect(url_for('manage_users'))

            else:
                return "No Users present in group!!!"

    return render_template('removeParticipant.html',form=form,grpname=grpname)

@app.route("/manage/creategroup", methods=['GET','POST'])
@login_required
def createNewgroup():
    form = CreateGroup()
    if form.validate_on_submit():
        grpToCreate= form.groupname.data
        group_exists = Group.query.filter_by(groupname=grpToCreate).all()
        if not group_exists:
            newGroup = Group(groupname=grpToCreate, owner=current_user.username)
            newGroupUser = GroupUsers(groupname=grpToCreate, user_name=current_user.username)
            db.session.add(newGroup)
            db.session.add(newGroupUser)
            #vdb.session.commit()
            if current_user.username != 'groupadmin':
                newGroupUser1 = GroupUsers(groupname = grpToCreate, user_name = 'groupadmin')
                db.session.add(newGroupUser1)



            db.session.commit()

            flash("Group Created Successfully")

        else:
            flash("Group already exists!!!")

        return redirect(url_for('createNewgroup'))

    return render_template("CreateGroup.html", form=form)
@app.route("/manage/deletegroup", methods=['GET','POST'])
@login_required
def deleteGroup():
    form = DeleteGroup()
    group_exists = Group.query.filter_by(owner=current_user.username).all()
    if current_user.username == 'groupadmin':
        group_exists = Group.query.all()

    flag = False
    if group_exists:
        flag=True
        grp = [grp.groupname for grp in group_exists]
        form.groupname.choices = grp
        if form.validate_on_submit():
            selected_group=  form.groupname.data
            [Group.query.filter_by(groupname=grp).delete() for grp in selected_group]
            db.session.commit()
            flash("Group deleted successfully...")

    return render_template("DeleteGroup.html", form=form, grp_exists=flag)

@app.route("/manage/addUsers",methods=['GET','POST'])
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

@app.route("/manage/DeleteUsers", methods=['GET','POST'])
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
    if 'token' in request.args:
        token = request.args['token']
        print(token)
        user = User.query.filter_by(username='groupadmin').first()
        if user.password == token:
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
        else:
            return {"Status": "Error", "message": "Token Invalid"}
    else:
        return {"Status": "Error", "message": "No token field provided"}

@app.route('/rest/deleteusers', methods=['GET','POST'])
def DeleteUsers_api():
    if 'token' in request.args:
        token = request.args['token']
        print(token)
        user = User.query.filter_by(username='groupadmin').first()
        if user.password == token:
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
        else:
            return {"Status": "Error", "message": "Token Invalid"}

    else:
        return {"Status": "Error", "message": "No token field provided"}


@app.route("/session",methods=['GET','POST'])
@login_required
def session():
    if 'groupname' in request.args:
        grp = request.args["groupname"]
    return render_template('session.html',user=current_user.username, group=grp)
def messageReceived(methods=['GET','POST']):
    print('Message was received...')

@socketio.on('my event')
def handle_my_custom_event(json,methods=['GET','POST']):
    print('Event received: ' +str(json))
    socketio.emit('my response', json, callback=messageReceived)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('login'))