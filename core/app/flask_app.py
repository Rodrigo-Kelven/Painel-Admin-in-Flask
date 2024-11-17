from flask import Flask
from datetime import timedelta
import os
from models import db
from register_router import register_router

# Configurações
# utilize funcoes, o codigo fica mais organizado, de facio alteração e compreensão
def create_app():

    app = Flask(__name__)

    app.config['SECRET_KEY'] = os.urandom(24)  # Chave secreta para segurança
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db' # banco de dados
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['REMEMBER_COOKIE_DURATION'] = timedelta(hours=1)  # Definindo o tempo da sessão para 7 dias

    # Depois de configurar o app
    db.init_app(app)

    with app.app_context():
        db.create_all()  # Criação do banco de dados, caso ainda não exista

    register_router(app)

    return app
