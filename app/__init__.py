from flask import Flask
from .routes.routes import main

def create_app():
   app = Flask(__name__)
   app.config['SECRET_KEY'] = 'change-me-in-prod'
   app.register_blueprint(main)
   return app
