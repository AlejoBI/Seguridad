<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sistema CRUD - Laboratorio de Seguridad</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <nav class="navbar">
        <div class="container">
            <h1>🔬 Sistema CRUD - Lab Seguridad</h1>
            <ul class="nav-menu">
                <li><a href="index.php">Inicio</a></li>
                <li><a href="login.php">Login</a></li>
                <li><a href="usuarios.php">Usuarios</a></li>
                <li><a href="productos.php">Productos</a></li>
            </ul>
        </div>
    </nav>

    <div class="container">
        <div class="hero">
            <h2>🎯 Bienvenido al Laboratorio de Seguridad</h2>
            <p class="subtitle">Sistema CRUD Vulnerable para Análisis con OWASP ZAP</p>
            
            <div class="warning-box">
                <h3>⚠️ ADVERTENCIA</h3>
                <p>Esta aplicación contiene vulnerabilidades <strong>INTENCIONALMENTE</strong> para fines educativos.</p>
                <p><strong>NO usar en producción ni exponer a internet.</strong></p>
            </div>

            <div class="features">
                <div class="feature-card">
                    <h3>👥 Gestión de Usuarios</h3>
                    <p>CRUD completo de usuarios con múltiples vulnerabilidades</p>
                    <ul>
                        <li>SQL Injection en login</li>
                        <li>XSS en búsqueda</li>
                        <li>CSRF en operaciones</li>
                    </ul>
                    <a href="usuarios.php" class="btn">Ver Usuarios</a>
                </div>

                <div class="feature-card">
                    <h3>📦 Gestión de Productos</h3>
                    <p>CRUD de productos con vulnerabilidades adicionales</p>
                    <ul>
                        <li>XSS Almacenado</li>
                        <li>Broken Access Control</li>
                        <li>Sensitive Data Exposure</li>
                    </ul>
                    <a href="productos.php" class="btn">Ver Productos</a>
                </div>

                <div class="feature-card">
                    <h3>🔐 Sistema de Login</h3>
                    <p>Autenticación vulnerable</p>
                    <ul>
                        <li>SQL Injection crítico</li>
                        <li>Sesiones inseguras</li>
                        <li>Credenciales débiles</li>
                    </ul>
                    <a href="login.php" class="btn">Iniciar Sesión</a>
                </div>
            </div>

            <div class="info-box">
                <h3>📊 Vulnerabilidades Implementadas</h3>
                <div class="vuln-list">
                    <span class="badge critical">🔴 SQL Injection</span>
                    <span class="badge high">🟠 XSS Reflejado</span>
                    <span class="badge high">🟠 XSS Almacenado</span>
                    <span class="badge high">🟠 CSRF</span>
                    <span class="badge critical">🔴 Broken Authentication</span>
                    <span class="badge high">🟠 Sensitive Data Exposure</span>
                    <span class="badge high">🟠 Broken Access Control</span>
                    <span class="badge medium">🟡 Security Misconfiguration</span>
                </div>
            </div>

            <div class="instructions">
                <h3>🔍 Cómo Usar Este Lab</h3>
                <ol>
                    <li><strong>Explorar:</strong> Navega por las diferentes secciones</li>
                    <li><strong>Analizar:</strong> Usa OWASP ZAP para escanear la aplicación</li>
                    <li><strong>Documentar:</strong> Registra todas las vulnerabilidades encontradas</li>
                    <li><strong>Corregir:</strong> Implementa las correcciones en app_corregida/</li>
                    <li><strong>Verificar:</strong> Re-escanea y compara resultados</li>
                </ol>
            </div>

            <div class="test-credentials">
                <h3>🔑 Credenciales de Prueba</h3>
                <div class="credentials">
                    <div>
                        <strong>Usuario:</strong> admin<br>
                        <strong>Password:</strong> admin123
                    </div>
                    <div>
                        <strong>Usuario:</strong> user<br>
                        <strong>Password:</strong> user123
                    </div>
                </div>
                <p class="note">💡 <strong>Tip:</strong> Intenta SQL Injection: <code>' OR '1'='1</code></p>
            </div>
        </div>
    </div>

    <footer>
        <p>🔬 Laboratorio de Seguridad - Escenario 2 | ⚠️ Solo para fines educativos</p>
    </footer>
</body>
</html>
