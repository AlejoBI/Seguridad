"""
Aplicación Web Vulnerable - Ejemplo para Análisis de Seguridad
ADVERTENCIA: Este código contiene múltiples vulnerabilidades intencionalmente.
NO usar en producción.
"""

import os
import pickle
import hashlib
from flask import Flask, request, render_template_string, redirect, send_file

app = Flask(__name__)

# VULNERABILIDAD 1: Hardcoded Secrets
SECRET_KEY = "mi_clave_super_secreta_123"
DATABASE_PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdef"

# VULNERABILIDAD 2: Weak Cryptography - MD5
def hash_password(password):
    """Usa MD5 para hashear contraseñas (INSEGURO)"""
    return hashlib.md5(password.encode()).hexdigest()

# VULNERABILIDAD 3: SQL Injection
def get_user(username):
    """Consulta SQL vulnerable a inyección"""
    import sqlite3
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # SQL Injection: concatenación directa sin sanitización
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    return result

# VULNERABILIDAD 4: Command Injection
def ping_server(host):
    """Ejecuta comando del sistema sin validación"""
    # Command Injection: ejecución directa de input del usuario
    result = os.system(f"ping -n 1 {host}")
    return result

# VULNERABILIDAD 5: Path Traversal
@app.route('/download')
def download_file():
    """Descarga archivos sin validar la ruta"""
    filename = request.args.get('file')
    # Path Traversal: no valida '../' en la ruta
    return send_file(f"uploads/{filename}")

# VULNERABILIDAD 6: XSS (Cross-Site Scripting)
@app.route('/search')
def search():
    """Búsqueda vulnerable a XSS"""
    query = request.args.get('q', '')
    # XSS: renderiza input del usuario sin escapar
    html = f"""
    <html>
        <body>
            <h1>Resultados para: {query}</h1>
            <p>Se encontraron resultados para tu búsqueda</p>
        </body>
    </html>
    """
    return render_template_string(html)

# VULNERABILIDAD 7: Insecure Deserialization
@app.route('/load_data', methods=['POST'])
def load_data():
    """Carga datos serializados sin validación"""
    data = request.data
    # Insecure Deserialization: pickle sin validación
    obj = pickle.loads(data)
    return str(obj)

# VULNERABILIDAD 8: Missing CSRF Protection
@app.route('/transfer', methods=['POST'])
def transfer_money():
    """Transferencia sin protección CSRF"""
    to = request.form.get('to')
    amount = request.form.get('amount')
    # No hay validación de token CSRF
    return f"Transferencia de ${amount} a {to} completada"

# VULNERABILIDAD 9: Weak Random
@app.route('/generate_token')
def generate_token():
    """Genera token con generador débil"""
    import random
    # Weak Random: random en lugar de secrets
    token = ''.join([str(random.randint(0, 9)) for _ in range(10)])
    return token

# VULNERABILIDAD 10: Debug Mode Enabled
@app.route('/debug')
def debug_info():
    """Expone información sensible en debug"""
    return {
        'secret_key': SECRET_KEY,
        'db_password': DATABASE_PASSWORD,
        'api_key': API_KEY,
        'env': dict(os.environ)
    }

# VULNERABILIDAD 11: Open Redirect
@app.route('/redirect')
def redirect_user():
    """Redirección abierta sin validación"""
    url = request.args.get('url')
    return redirect(url)

# VULNERABILIDAD 12: Eval injection
@app.route('/calc')
def calculator():
    """Calculadora vulnerable a eval injection"""
    expr = request.args.get('expr', '1+1')
    # Eval Injection: eval directo de input del usuario
    result = eval(expr)
    return str(result)

@app.route('/')
def index():
    """Página principal"""
    return """
    <html>
        <head><title>Aplicación Vulnerable</title></head>
        <body>
            <h1>Aplicación de Prueba - Vulnerable</h1>
            <ul>
                <li><a href="/search?q=test">Búsqueda (XSS)</a></li>
                <li><a href="/download?file=test.txt">Descargar (Path Traversal)</a></li>
                <li><a href="/redirect?url=http://example.com">Redirect</a></li>
                <li><a href="/calc?expr=2+2">Calculadora (Eval)</a></li>
                <li><a href="/generate_token">Generar Token</a></li>
                <li><a href="/debug">Debug Info</a></li>
            </ul>
        </body>
    </html>
    """

if __name__ == '__main__':
    # VULNERABILIDAD 13: Debug mode en producción
    app.run(debug=True, host='0.0.0.0', port=5000)
