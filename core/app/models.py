from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

db = SQLAlchemy()

# Modelos de usuário
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # Campo para verificar se o usuário é administrador

    # Criptografar a senha fornecida pelo usuário
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    # Checa a senha fornecida pelo usuário
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    # Verifica seo usuario é um admin
    def is_admin_user(self):
        return self.is_admin