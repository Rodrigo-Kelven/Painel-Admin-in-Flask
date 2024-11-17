from flask import render_template, redirect, url_for, flash
from forms import RegistrationForm, LoginForm
from flask_migrate import Migrate
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash
from flask_wtf.csrf import CSRFProtect

from forms import *
from models import *



def register_router(app):
    login_manager = LoginManager(app)
    login_manager.login_view = 'login'  # Redireciona para a página de login se o usuário não estiver autenticado
    #csrf = CSRFProtect(app)
    #migrate = Migrate(app, db)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    

    logs_users = []

    @app.route("/logs_users", methods=['GET'])
    @login_required
    def loggs():
        return logs_users

    # Página inicial
    @app.route('/')
    def home():
        return render_template('home.html')

    # Página de registro
    @app.route('/register', methods=['GET', 'POST'])
    def register():

        form = RegistrationForm()
        if form.validate_on_submit():
            username = form.username.data
            password = form.password_confirmation.data

            log = {
                "Username":f"{username}",
                "Password":f"{password}",
            }
            
            # Buscar usuário no banco .firts() primeiro resultado
            user = User.query.filter_by(username=username).first()
            if user:
                flash('Nome de usuário já existe!', 'danger')
                return redirect(url_for('register'))

            # Criptografar senha e salvar no banco
            new_user = User(username=username)
            logs_users.append(log)
            print(f"Dados do usuario: {log}")
            new_user.set_password(password)  # Criptografar a senha fornecida pelo usuário
            db.session.add(new_user) # abre uma nova sessao, coloca o usuario nesta sessao
            db.session.commit() # commita o novo user no db


            flash('Conta criada com sucesso!', 'success')
            return redirect(url_for('login'))

        return render_template('register.html', form=form) # primeiro o que esta no html, depois o que sera passado


    # Página de login
    @app.route('/login', methods=['GET', 'POST'])
    def login():

        form = LoginForm()
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data

            # Buscar usuário no banco
            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password):
                # Faz login do usuário e mantém a sessão após fechar o navegador
                login_user(user, remember=True)  # A sessão será persistente
                flash('Login realizado com sucesso!', 'success')
                return redirect(url_for('home'))
            else:
                flash('Nome de usuário ou senha inválidos', 'danger')
                return redirect(url_for('login')) # Redireciona para a página de login

        return render_template('login.html', form=form) # primeiro o que esta no html, depois o que sera passado

    # Página de logout
    @app.route('/logout')
    @login_required # login requerido, somente se o usuario estiver logado
    def logout():
        logout_user() # Encerra a sessão do usuário
        flash('Logout realizado com sucesso!', 'success')
        return redirect(url_for('login')) # Redireciona para a página de login



    # Página de perfil (atualizar e excluir conta)
    @app.route('/profile', methods=['GET', 'POST'])
    @login_required # login requerido, somente se o usuario estiver logado
    def profile():
        form = UpdateProfileForm()

        if form.validate_on_submit():
            # Atualizando o nome de usuário
            if form.username.data and form.username.data != current_user.username:
                # Verifica se o nome de usuário já existe no banco
                existing_user = User.query.filter_by(username=form.username.data).first()
                if existing_user:
                    flash('Nome de usuário já está em uso.', 'danger')
                    return redirect(url_for('profile'))
                current_user.username = form.username.data

            # Atualizando a senha
            if form.password.data:
                current_user.set_password(form.password.data)

            db.session.commit()
            flash('Dados atualizados com sucesso!', 'success')
            return redirect(url_for('profile'))

        return render_template('profile.html', form=form) # primeiro o que esta no html, depois o que sera passado



    # Rota para excluir conta
    @app.route('/delete_account', methods=['POST'])
    @login_required # login requerido, somente se o usuario estiver logado
    def delete_account():
        form = DeleteAccountForm()
        if form.validate_on_submit():
            user = current_user
            db.session.delete(user)
            db.session.commit()
            logout_user()  # Realiza o logout após excluir a conta
            flash('Sua conta foi excluída com sucesso!', 'success')
            return redirect(url_for('login'))  # Redireciona para a página de login após a exclusão

    # Definindo a Rota do Admin
    @app.route('/admin')
    @login_required  # Garante que o usuário esteja logado / # login requerido, somente se o usuario estiver logado
    def admin_dashboard():
        # Verifica se o usuário logado é o admin
        if current_user.username != 'admin':  # Só o admin pode acessar
            return redirect(url_for('admin_dashboard'))  # Redireciona para a página inicial se não for admin

        # Buscar todos os usuários registrados no banco de dados
        users = User.query.all()
        
        # Passa a lista de usuários para o template
        return render_template('admin.html', users=users) # primeiro o que esta no html, depois o que sera passado




    @app.route('/admin/create', methods=['GET', 'POST'])
    @login_required # login requerido, somente se o usuario estiver logado
    def create_user():
        if current_user.username != 'admin':  # Apenas o admin pode criar novos usuários
            return redirect(url_for('home'))

        form = RegistrationForm()

        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data
            #hashed_password = generate_password_hash(password, method='sha256')

            # Verfrom datetime import timedeltaificar se o usuário já existe
            new_user = User.query.filter_by(username=username).first()
            if new_user:
                flash('Nome de usuário já existe!', 'danger')
                return redirect(url_for('register'))
            
            # Criptografar senha e salvar no banco
            new_user = User(username=username)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash('Novo usuário criado com sucesso!', 'success')
            return redirect(url_for('admin_dashboard'))

        return render_template('create_user.html', form=form) # primeiro o que esta no html, depois o que sera passado



    # Rota para editar um usuário
    @app.route('/admin/edit/<int:user_id>', methods=['GET', 'POST'])
    @login_required # login requerido, somente se o usuario estiver logado
    def edit_user(user_id):
        if current_user.username != 'admin':  # Apenas o admin pode editar usuários
            return redirect(url_for('index'))

        user = User.query.get_or_404(user_id)

        form = EditUserForm(obj=user)  # Preenche o formulário com os dados do usuário
        
        if form.validate_on_submit():
            # Atualizando o nome de usuário e email
            user.username = form.username.data

            # Atualizando a senha, se fornecida
            if form.password.data:
                user.password_hash = generate_password_hash(form.password.data, method='sha256')


            db.session.commit()
            flash('Usuário atualizado com sucesso!', 'success')
            return redirect(url_for('admin_dashboard'))

        return render_template('edit_user.html', user=user, form=form) # primeiro o que esta no html, depois o que sera passado



    # Rota para deletar um usuário
    @app.route('/admin/delete/<int:user_id>', methods=['GET', 'POST'])
    @login_required # login requerido, somente se o usuario estiver logado
    def delete_user(user_id):
        if current_user.username != 'admin':  # Apenas o admin pode deletar usuários
            return redirect(url_for('index'))

        user = User.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        flash('Usuário deletado com sucesso!', 'success')
        return redirect(url_for('admin_dashboard'))
