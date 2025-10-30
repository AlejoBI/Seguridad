<?php
require_once 'config.php';

// VULNERABILIDAD: Sin verificación de autenticación
// SEVERIDAD: HIGH
// if (!isLoggedIn()) {
//     header('Location: login.php');
//     exit();
// }

$conn = getConnection();
$search = isset($_GET['search']) ? $_GET['search'] : '';
$message = '';

// VULNERABILIDAD: Sin protección CSRF en DELETE
if (isset($_GET['delete'])) {
    $id = $_GET['delete'];
    
    // VULNERABILIDAD: SQL Injection en DELETE
    // SEVERIDAD: CRITICAL
    $query = "DELETE FROM usuarios WHERE id = $id";
    mysqli_query($conn, $query);
    $message = "Usuario eliminado";
}

// VULNERABILIDAD: Sin protección CSRF en operaciones POST
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (isset($_POST['action'])) {
        if ($_POST['action'] == 'create') {
            $username = $_POST['username'];
            $email = $_POST['email'];
            $password = $_POST['password'];
            $role = $_POST['role'] ?? 'user';
            
            // VULNERABILIDAD: Password sin hash
            // SEVERIDAD: CRITICAL
            // VULNERABILIDAD: SQL Injection en INSERT
            $query = "INSERT INTO usuarios (username, email, password, role) 
                      VALUES ('$username', '$email', '$password', '$role')";
            
            if (mysqli_query($conn, $query)) {
                $message = "Usuario creado exitosamente";
            } else {
                // VULNERABILIDAD: Exposición de errores SQL
                $message = "Error: " . mysqli_error($conn);
            }
        }
        
        if ($_POST['action'] == 'update') {
            $id = $_POST['id'];
            $username = $_POST['username'];
            $email = $_POST['email'];
            $role = $_POST['role'];
            
            // VULNERABILIDAD: SQL Injection en UPDATE
            // SEVERIDAD: CRITICAL
            $query = "UPDATE usuarios SET username='$username', email='$email', role='$role' WHERE id=$id";
            
            if (mysqli_query($conn, $query)) {
                $message = "Usuario actualizado";
            }
        }
    }
}

// VULNERABILIDAD: XSS Reflejado - Sin sanitizar búsqueda
// SEVERIDAD: HIGH
if ($search != '') {
    // La búsqueda se refleja sin escapar en el HTML
    $query = "SELECT * FROM usuarios WHERE username LIKE '%$search%' OR email LIKE '%$search%'";
} else {
    $query = "SELECT * FROM usuarios ORDER BY id DESC";
}

$result = mysqli_query($conn, $query);
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gestión de Usuarios</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <nav class="navbar">
        <div class="container">
            <h1>👥 Gestión de Usuarios</h1>
            <ul class="nav-menu">
                <li><a href="index.php">Inicio</a></li>
                <li><a href="usuarios.php" class="active">Usuarios</a></li>
                <li><a href="productos.php">Productos</a></li>
                <li><a href="logout.php">Salir</a></li>
            </ul>
        </div>
    </nav>

    <div class="container">
        <?php if ($message): ?>
            <!-- VULNERABILIDAD: XSS - Sin escapar mensaje -->
            <div class="alert alert-success">
                <?php echo $message; ?>
            </div>
        <?php endif; ?>

        <div class="section">
            <h2>🔍 Buscar Usuarios</h2>
            <!-- VULNERABILIDAD: XSS Reflejado en búsqueda -->
            <form method="GET" action="" class="search-form">
                <input type="text" name="search" value="<?php echo $search; ?>" 
                       placeholder="Buscar por nombre o email...">
                <button type="submit" class="btn">Buscar</button>
            </form>
            
            <?php if ($search): ?>
                <!-- VULNERABILIDAD: XSS - El término de búsqueda se muestra sin escapar -->
                <p class="search-result">Resultados para: <strong><?php echo $search; ?></strong></p>
            <?php endif; ?>
            
            <div class="vulnerability-hint">
                <p>💡 Intenta XSS: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></p>
            </div>
        </div>

        <div class="section">
            <h2>➕ Crear Usuario</h2>
            <!-- VULNERABILIDAD: Sin token CSRF -->
            <form method="POST" action="" class="user-form">
                <input type="hidden" name="action" value="create">
                
                <div class="form-group">
                    <label>Usuario:</label>
                    <input type="text" name="username" required>
                </div>
                
                <div class="form-group">
                    <label>Email:</label>
                    <input type="email" name="email" required>
                </div>
                
                <div class="form-group">
                    <label>Contraseña:</label>
                    <!-- VULNERABILIDAD: Password en texto plano -->
                    <input type="text" name="password" required>
                    <small>⚠️ Se guarda en texto plano (vulnerable)</small>
                </div>
                
                <div class="form-group">
                    <label>Rol:</label>
                    <!-- VULNERABILIDAD: Sin validación de roles -->
                    <select name="role">
                        <option value="user">Usuario</option>
                        <option value="admin">Administrador</option>
                    </select>
                </div>
                
                <button type="submit" class="btn btn-primary">Crear Usuario</button>
            </form>
        </div>

        <div class="section">
            <h2>📋 Lista de Usuarios</h2>
            <div class="table-responsive">
                <table class="table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Usuario</th>
                            <th>Email</th>
                            <th>Password</th>
                            <th>Rol</th>
                            <th>Acciones</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php while ($user = mysqli_fetch_assoc($result)): ?>
                        <tr>
                            <td><?php echo $user['id']; ?></td>
                            <!-- VULNERABILIDAD: XSS - Sin escapar datos de usuario -->
                            <td><?php echo $user['username']; ?></td>
                            <td><?php echo $user['email']; ?></td>
                            <!-- VULNERABILIDAD: Exposición de passwords -->
                            <td class="password-visible"><?php echo $user['password']; ?></td>
                            <td><?php echo $user['role']; ?></td>
                            <td>
                                <!-- VULNERABILIDAD: CSRF en DELETE vía GET -->
                                <a href="?delete=<?php echo $user['id']; ?>" 
                                   class="btn btn-danger btn-sm"
                                   onclick="return confirm('¿Eliminar usuario?')">
                                    Eliminar
                                </a>
                                <button onclick="editUser(<?php echo $user['id']; ?>, '<?php echo $user['username']; ?>', 
                                                          '<?php echo $user['email']; ?>', '<?php echo $user['role']; ?>')" 
                                        class="btn btn-warning btn-sm">
                                    Editar
                                </button>
                            </td>
                        </tr>
                        <?php endwhile; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Modal de edición (oculto por defecto) -->
        <div id="editModal" class="modal" style="display:none;">
            <div class="modal-content">
                <h3>✏️ Editar Usuario</h3>
                <!-- VULNERABILIDAD: Sin token CSRF -->
                <form method="POST" action="">
                    <input type="hidden" name="action" value="update">
                    <input type="hidden" name="id" id="edit_id">
                    
                    <div class="form-group">
                        <label>Usuario:</label>
                        <input type="text" name="username" id="edit_username" required>
                    </div>
                    
                    <div class="form-group">
                        <label>Email:</label>
                        <input type="email" name="email" id="edit_email" required>
                    </div>
                    
                    <div class="form-group">
                        <label>Rol:</label>
                        <select name="role" id="edit_role">
                            <option value="user">Usuario</option>
                            <option value="admin">Administrador</option>
                        </select>
                    </div>
                    
                    <button type="submit" class="btn btn-primary">Actualizar</button>
                    <button type="button" onclick="closeModal()" class="btn">Cancelar</button>
                </form>
            </div>
        </div>
    </div>

    <script>
        // VULNERABILIDAD: XSS en parámetros de función
        function editUser(id, username, email, role) {
            document.getElementById('edit_id').value = id;
            document.getElementById('edit_username').value = username;
            document.getElementById('edit_email').value = email;
            document.getElementById('edit_role').value = role;
            document.getElementById('editModal').style.display = 'block';
        }
        
        function closeModal() {
            document.getElementById('editModal').style.display = 'none';
        }
    </script>
</body>
</html>
<?php mysqli_close($conn); ?>
