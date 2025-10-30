<?php
// VULNERABILIDAD: Hardcoded credentials
// SEVERIDAD: CRITICAL
define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', ''); // Contraseña vacía en desarrollo
define('DB_NAME', 'lab_seguridad');

// VULNERABILIDAD: Error reporting habilitado
// SEVERIDAD: MEDIUM
error_reporting(E_ALL);
ini_set('display_errors', 1);

// VULNERABILIDAD: Sin prepared statements
// SEVERIDAD: CRITICAL
function getConnection() {
    $conn = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    
    if (!$conn) {
        // VULNERABILIDAD: Exposición de información sensible
        die("Error de conexión: " . mysqli_connect_error());
    }
    
    // VULNERABILIDAD: Sin charset seguro
    // mysqli_set_charset($conn, "utf8mb4"); // Comentado intencionalmente
    
    return $conn;
}

// VULNERABILIDAD: Sesiones sin configuración segura
// SEVERIDAD: HIGH
session_start();
// session_regenerate_id(true); // No se regenera el ID
// ini_set('session.cookie_httponly', 1); // No tiene HttpOnly
// ini_set('session.cookie_secure', 1); // No tiene Secure flag

function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

function getCurrentUser() {
    if (isLoggedIn()) {
        return $_SESSION['username'];
    }
    return null;
}

// VULNERABILIDAD: Sin sanitización de inputs
// SEVERIDAD: CRITICAL
function sanitize($data) {
    // Esta función NO hace nada, solo retorna el dato sin sanitizar
    // Intencionalmente vulnerable
    return $data;
}

// VULNERABILIDAD: Sin validación CSRF
// SEVERIDAD: HIGH
function generateCSRFToken() {
    // Función vacía - no genera token
    return '';
}

function verifyCSRFToken($token) {
    // Siempre retorna true - no verifica
    return true;
}
?>
