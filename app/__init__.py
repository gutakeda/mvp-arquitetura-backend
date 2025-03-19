from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flasgger import Swagger
from sqlalchemy import event
from sqlalchemy.engine import Engine
from dotenv import load_dotenv


db = SQLAlchemy()

# Define the function to enable foreign key support
def _set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON;")
    cursor.close()

def create_app():
    # Carregar variáveis de ambiente do arquivo .env
    load_dotenv()

    app = Flask(__name__)
    app.config.from_object('app.config.Config')

    db.init_app(app)

    # Enable foreign key support for SQLite
    @event.listens_for(Engine, "connect")
    def _connect_sqlite(dbapi_connection, connection_record):
        _set_sqlite_pragma(dbapi_connection, connection_record)

    # Initialize Swagger (Flasgger)
    swagger = Swagger(app)

    swagger.config['securityDefinitions'] = {
    'BearerAuth': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization',
        'description': 'O token JWT deve ser enviado no cabeçalho Authorization com o prefixo "Bearer "'
    }
}

    from app.routes import api
    app.register_blueprint(api)
    CORS(app)

    return app