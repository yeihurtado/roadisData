
from flask import Flask, jsonify, render_template, request, redirect, url_for, make_response,after_this_request
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token, create_refresh_token,
    set_access_cookies, set_refresh_cookies, unset_jwt_cookies, jwt_manager,get_jwt_identity,verify_jwt_in_request
)
from werkzeug.security import check_password_hash
from models import Usuario
from extensions import db

def init_routes(app):
    jwt = JWTManager(app)  # Asegúrate de que JWTManager esté inicializado con la app

    @jwt.unauthorized_loader
    def unauthorized_callback(error):
        # Redirecciona a la página de login si no hay un token válido
        return redirect(url_for('login'))


    @app.route('/login', methods=['GET', 'POST'])
    def login():
            # Verifica si ya hay un usuario logueado
        try:
            verify_jwt_in_request(optional=True)
            current_user = get_jwt_identity()
            if current_user:
                return redirect(url_for('/'))  # Redirige a index si el usuario ya está logueado
        except Exception as e:
            # En caso de cualquier excepción, simplemente continúa mostrando la página de login
            print(e)
    

        if request.method == 'POST':
            username = request.json.get('username')
            password = request.json.get('password')
            user = Usuario.query.filter_by(username=username).first()
            
            if user and user.check_password(password):
                access_token = create_access_token(identity=user.id)
                refresh_token = create_refresh_token(identity=user.id)
                response = jsonify({'login': True})
                set_access_cookies(response, access_token)
                set_refresh_cookies(response, refresh_token)
                return response

                #return response            
            return jsonify({"msg": "Bad username or password"}), 401
        return render_template('login.html')

    
    @app.route('/logout', methods=['POST'])
    def logout():
        response = make_response(redirect(url_for('login')))  # Crea una respuesta que redirige al login
        unset_jwt_cookies(response)  # Elimina las cookies JWT
        return response  # Retorna la respuesta modificada
    
 
    @app.route('/')
    @jwt_required()
    def index():
        @after_this_request
        def add_header(response):
            response.headers['Cache-Control'] = 'no-store'
            return response
        return render_template('index.html')
    
    @app.route('/index')
    def redirect_to_home():
        @after_this_request
        def add_header(response):
            response.headers['Cache-Control'] = 'no-store'
            return response
        return redirect(url_for('index'))

    @app.route('/contacto')
    @jwt_required()
    def contacto():
        return render_template('contacto.html')

    @app.route('/about')
    @jwt_required()
    def about():
        return render_template('about.html')
    
#callbacks de errores

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_data):
        return redirect(url_for('login'))

    @jwt.invalid_token_loader
    def invalid_token_callback(error):  # Callback invocado cuando un token inválido es proporcionado.
        """return jsonify({
            'status': 401,
            'sub_status': 41,
            'msg': 'Invalid token. Please log in again.'
        }), 401"""
        return redirect(url_for('login'))

    @jwt.unauthorized_loader
    def missing_token_callback(error):  # Callback invocado cuando falta el token.
       
       return redirect(url_for('login'))

