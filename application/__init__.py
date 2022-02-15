from flask import Flask
from config import Config


app = Flask(__name__)
from application import routes

app.config['SQLALCHEMY_DATABASE_URI'] = Config.db_config
app.config['SECRET_KEY'] = Config.SECRET_KEY
app.config['DEBUG'] = Config.Debug