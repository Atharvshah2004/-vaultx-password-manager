from flask import Flask
from config import Config
from pymongo import MongoClient

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Connect to MongoDB
    client = MongoClient(app.config["MONGO_URI"])
    app.db = client.get_database()

    # Register all route blueprints
    from app.routes import main_bp
    app.register_blueprint(main_bp)

    return app