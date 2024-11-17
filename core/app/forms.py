from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo

# Formulario para registro de Usuarios
class RegistrationForm(FlaskForm):
    username = StringField('Nome de usuário', validators=[DataRequired()])
    password = PasswordField('Senha', validators=[DataRequired()])
    password_confirmation = PasswordField('Confirmar senha', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

# Formulario para Login de Usuarios
class LoginForm(FlaskForm):
    username = StringField('Nome de usuário', validators=[DataRequired()])
    password = PasswordField('Senha', validators=[DataRequired()])
    submit = SubmitField('Login')
    
# Formulário para atualizar dados do perfil
class UpdateProfileForm(FlaskForm):
    username = StringField('Novo Nome de Usuário')
    password = PasswordField('Nova Senha')
    password_confirmation = PasswordField('Confirmar Nova Senha', validators=[EqualTo('password')])
    submit = SubmitField('Salvar alterações')
    
# Formulario de edição para o usuário
class EditUserForm(FlaskForm):
    username = StringField('Nome de Usuário', validators=[DataRequired()])
    password = PasswordField('Nova Senha (deixe em branco para não alterar)')
    password_confirmation = PasswordField('Confirmar nova senha', validators=[EqualTo('password', message='As senhas devem coincidir.')])
    submit = SubmitField('Salvar alterações')

# Formulario para deletar conta do usuario
class DeleteAccountForm(FlaskForm):
    submit = SubmitField('Excluir Conta')