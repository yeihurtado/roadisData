from flask import Flask
from extensions import db, jwt
from config import Config
from routes import init_routes

app = Flask(__name__)
app.config.from_object(Config)
app.config['JWT_COOKIE_CSRF_PROTECT'] = True  # Asegura CSRF protection
app.config['JWT_COOKIE_SECURE'] = True  # Solo envía cookies sobre HTTPS
db.init_app(app)
jwt.init_app(app)

init_routes(app)

if __name__ == '__main__':
   app.run(debug=True, port=5000)
