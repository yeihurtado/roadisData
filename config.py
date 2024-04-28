import os

class Config:
    SECRET_KEY = 'tu_clave_secreta'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    JWT_SECRET_KEY = 'otra_clave_secreta_para_jwt'
    JWT_TOKEN_LOCATION = ['cookies']  # Utilizar tokens en cookies
    JWT_ACCESS_COOKIE_PATH = '/'  # Rutas en las que el access cookie será enviado
    JWT_REFRESH_COOKIE_PATH = '/token/refresh'  # Ruta para renovar el access token
    JWT_COOKIE_SECURE = True  # Solo enviar cookies sobre HTTPS
    JWT_COOKIE_CSRF_PROTECT = True  # Activar protección CSRF
    JWT_ACCESS_COOKIE_NAME = 'access_token_cookie'  # Nombre del access cookie
    JWT_REFRESH_COOKIE_NAME = 'refresh_token_cookie'  # Nombre del refresh cookie
    JWT_COOKIE_HTTPONLY = True  # Hacer que las cookies sean HttpOnly
    
