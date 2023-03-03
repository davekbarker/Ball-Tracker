import os
import sys
from flask import Flask

def create_app():
    app = Flask(__name__)

    from . import auth
    app.register_blueprint(auth.bp)

    mydatabase_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    sys.path.append(mydatabase_path)

    from .main import main
    app.register_blueprint(main.bp)

    from . import database
    database.init_app(app)

    return app