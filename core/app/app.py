from flask_app import create_app

# se o arquivo for o principal, execute...
if __name__ == '__main__':
    app = create_app()
    app.run(debug=False)

# lembrar de esquecer blueprint