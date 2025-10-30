<?php
session_start();

// VULNERABILIDAD: Sin destrucción completa de sesión
// SEVERIDAD: MEDIUM
session_unset();
// session_destroy(); // No se destruye completamente

// VULNERABILIDAD: Cookie de sesión no se elimina
// SEVERIDAD: MEDIUM
// setcookie(session_name(), '', time()-3600, '/'); // No implementado

header('Location: login.php');
exit();
?>
