<?php
require_once 'config.php';

$error = '';
$success = '';

// VULNERABILIDAD: Sin protección CSRF
// SEVERIDAD: HIGH
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    
    $conn = getConnection();
    
    // VULNERABILIDAD: SQL Injection - Concatenación directa
    // SEVERIDAD: CRITICAL
    // No se usan prepared statements
    $query = "SELECT * FROM usuarios WHERE username = '$username' AND password = '$password'";
    
    // VULNERABILIDAD: Exposición de query en comentario
    // echo "<!-- Debug: $query -->";
    
    $result = mysqli_query($conn, $query);
    
    if ($result && mysqli_num_rows($result) > 0) {
        $user = mysqli_fetch_assoc($result);
        
        // VULNERABILIDAD: Sesión sin regenerar ID
        // SEVERIDAD: MEDIUM
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['role'] = $user['role'];
        
        // VULNERABILIDAD: Sin tiempo de expiración de sesión
        // $_SESSION['last_activity'] = time(); // No implementado
        
        header('Location: usuarios.php');
        exit();
    } else {
        // VULNERABILIDAD: Mensaje de error demasiado específico
        // SEVERIDAD: LOW
        $error = "Usuario o contraseña incorrectos. Query: $query";
    }
    
    mysqli_close($conn);
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Sistema CRUD</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="login-container">
        <div class="login-box">
            <h2>🔐 Iniciar Sesión</h2>
            
            <?php if ($error): ?>
                <!-- VULNERABILIDAD: XSS - Sin escapar output -->
                <div class="alert alert-danger">
                    <?php echo $error; ?>
                </div>
            <?php endif; ?>
            
            <div class="vulnerability-warning">
                <p>⚠️ Esta página es <strong>VULNERABLE</strong> a SQL Injection</p>
                <p>Intenta: <code>' OR '1'='1</code></p>
            </div>
            
            <!-- VULNERABILIDAD: Sin token CSRF -->
            <form method="POST" action="">
                <div class="form-group">
                    <label>Usuario:</label>
                    <!-- VULNERABILIDAD: Autocomplete habilitado -->
                    <input type="text" name="username" required>
                </div>
                
                <div class="form-group">
                    <label>Contraseña:</label>
                    <!-- VULNERABILIDAD: Autocomplete habilitado en password -->
                    <input type="password" name="password" required>
                </div>
                
                <button type="submit" class="btn btn-primary">Ingresar</button>
            </form>
            
            <div class="test-accounts">
                <h4>Cuentas de prueba:</h4>
                <ul>
                    <li>admin / admin123</li>
                    <li>user / user123</li>
                </ul>
            </div>
            
            <div class="sql-injection-hints">
                <h4>💡 Prueba SQL Injection:</h4>
                <ul>
                    <li><code>' OR '1'='1</code></li>
                    <li><code>admin' --</code></li>
                    <li><code>' OR 1=1 --</code></li>
                    <li><code>admin' OR '1'='1' --</code></li>
                </ul>
            </div>
            
            <p class="text-center">
                <a href="index.php">← Volver al inicio</a>
            </p>
        </div>
    </div>
</body>
</html>
