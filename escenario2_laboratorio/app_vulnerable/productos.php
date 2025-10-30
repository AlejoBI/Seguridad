<?php
require_once 'config.php';

$conn = getConnection();
$message = '';

// VULNERABILIDAD: Sin verificación de roles/permisos
// SEVERIDAD: HIGH (Broken Access Control)
// Cualquier usuario puede crear/editar/eliminar productos

// VULNERABILIDAD: Sin protección CSRF
if (isset($_GET['delete'])) {
    $id = $_GET['delete'];
    
    // VULNERABILIDAD: SQL Injection
    $query = "DELETE FROM productos WHERE id = $id";
    mysqli_query($conn, $query);
    $message = "Producto eliminado";
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (isset($_POST['action'])) {
        if ($_POST['action'] == 'create') {
            $nombre = $_POST['nombre'];
            $descripcion = $_POST['descripcion'];
            $precio = $_POST['precio'];
            $categoria = $_POST['categoria'];
            
            // VULNERABILIDAD: SQL Injection + XSS Almacenado
            // SEVERIDAD: CRITICAL
            // La descripción puede contener scripts maliciosos
            $query = "INSERT INTO productos (nombre, descripcion, precio, categoria) 
                      VALUES ('$nombre', '$descripcion', '$precio', '$categoria')";
            
            if (mysqli_query($conn, $query)) {
                $message = "Producto creado exitosamente";
            } else {
                $message = "Error: " . mysqli_error($conn);
            }
        }
        
        if ($_POST['action'] == 'comment') {
            $producto_id = $_POST['producto_id'];
            $comentario = $_POST['comentario'];
            $usuario = getCurrentUser() ?? 'Anónimo';
            
            // VULNERABILIDAD: XSS Almacenado en comentarios
            // SEVERIDAD: HIGH
            $query = "INSERT INTO comentarios (producto_id, usuario, comentario) 
                      VALUES ($producto_id, '$usuario', '$comentario')";
            
            mysqli_query($conn, $query);
            $message = "Comentario agregado";
        }
    }
}

$productos = mysqli_query($conn, "SELECT * FROM productos ORDER BY id DESC");
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gestión de Productos</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <nav class="navbar">
        <div class="container">
            <h1>📦 Gestión de Productos</h1>
            <ul class="nav-menu">
                <li><a href="index.php">Inicio</a></li>
                <li><a href="usuarios.php">Usuarios</a></li>
                <li><a href="productos.php" class="active">Productos</a></li>
                <li><a href="logout.php">Salir</a></li>
            </ul>
        </div>
    </nav>

    <div class="container">
        <?php if ($message): ?>
            <div class="alert alert-success">
                <?php echo $message; ?>
            </div>
        <?php endif; ?>

        <div class="section">
            <h2>➕ Crear Producto</h2>
            <div class="vulnerability-warning">
                <p>⚠️ <strong>Broken Access Control:</strong> Cualquier usuario puede crear productos (sin verificación de rol)</p>
                <p>⚠️ <strong>XSS Almacenado:</strong> La descripción no se sanitiza</p>
            </div>
            
            <!-- VULNERABILIDAD: Sin token CSRF -->
            <form method="POST" action="" class="product-form">
                <input type="hidden" name="action" value="create">
                
                <div class="form-group">
                    <label>Nombre:</label>
                    <input type="text" name="nombre" required>
                </div>
                
                <div class="form-group">
                    <label>Descripción:</label>
                    <textarea name="descripcion" rows="3" required></textarea>
                    <small class="vuln-hint">💡 Intenta: <code>&lt;img src=x onerror="alert('XSS')"&gt;</code></small>
                </div>
                
                <div class="form-group">
                    <label>Precio:</label>
                    <input type="number" step="0.01" name="precio" required>
                </div>
                
                <div class="form-group">
                    <label>Categoría:</label>
                    <input type="text" name="categoria" required>
                </div>
                
                <button type="submit" class="btn btn-primary">Crear Producto</button>
            </form>
        </div>

        <div class="section">
            <h2>📋 Lista de Productos</h2>
            <div class="products-grid">
                <?php while ($producto = mysqli_fetch_assoc($productos)): ?>
                <div class="product-card">
                    <h3><?php echo $producto['nombre']; ?></h3>
                    
                    <!-- VULNERABILIDAD: XSS Almacenado - Sin escapar HTML -->
                    <!-- SEVERIDAD: HIGH -->
                    <div class="product-description">
                        <?php echo $producto['descripcion']; ?>
                    </div>
                    
                    <p class="product-price">
                        <strong>Precio:</strong> $<?php echo $producto['precio']; ?>
                    </p>
                    
                    <p class="product-category">
                        <strong>Categoría:</strong> <?php echo $producto['categoria']; ?>
                    </p>
                    
                    <div class="product-actions">
                        <!-- VULNERABILIDAD: CSRF + Falta de autorización -->
                        <a href="?delete=<?php echo $producto['id']; ?>" 
                           class="btn btn-danger btn-sm"
                           onclick="return confirm('¿Eliminar producto?')">
                            Eliminar
                        </a>
                        <button onclick="showComments(<?php echo $producto['id']; ?>)" 
                                class="btn btn-info btn-sm">
                            Ver Comentarios
                        </button>
                    </div>
                    
                    <!-- Sección de comentarios -->
                    <div id="comments-<?php echo $producto['id']; ?>" class="comments-section" style="display:none;">
                        <h4>💬 Comentarios</h4>
                        
                        <?php
                        $comentarios = mysqli_query($conn, 
                            "SELECT * FROM comentarios WHERE producto_id = {$producto['id']} ORDER BY id DESC");
                        
                        while ($comentario = mysqli_fetch_assoc($comentarios)):
                        ?>
                        <div class="comment">
                            <strong><?php echo $comentario['usuario']; ?>:</strong>
                            <!-- VULNERABILIDAD: XSS Almacenado en comentarios -->
                            <p><?php echo $comentario['comentario']; ?></p>
                            <small><?php echo $comentario['fecha']; ?></small>
                        </div>
                        <?php endwhile; ?>
                        
                        <!-- VULNERABILIDAD: Sin token CSRF -->
                        <form method="POST" action="" class="comment-form">
                            <input type="hidden" name="action" value="comment">
                            <input type="hidden" name="producto_id" value="<?php echo $producto['id']; ?>">
                            
                            <textarea name="comentario" placeholder="Escribe un comentario..." required></textarea>
                            <small class="vuln-hint">💡 XSS: <code>&lt;script&gt;alert(document.cookie)&lt;/script&gt;</code></small>
                            
                            <button type="submit" class="btn btn-sm">Comentar</button>
                        </form>
                    </div>
                </div>
                <?php endwhile; ?>
            </div>
        </div>

        <div class="vulnerability-summary">
            <h3>🔴 Vulnerabilidades en esta página:</h3>
            <ul>
                <li><strong>XSS Almacenado:</strong> Descripción de productos y comentarios sin sanitizar</li>
                <li><strong>CSRF:</strong> Crear, eliminar productos y comentar sin token</li>
                <li><strong>Broken Access Control:</strong> Sin verificación de roles</li>
                <li><strong>SQL Injection:</strong> Todas las operaciones vulnerables</li>
            </ul>
        </div>
    </div>

    <script>
        function showComments(productId) {
            var commentsDiv = document.getElementById('comments-' + productId);
            if (commentsDiv.style.display === 'none') {
                commentsDiv.style.display = 'block';
            } else {
                commentsDiv.style.display = 'none';
            }
        }
    </script>
</body>
</html>
<?php mysqli_close($conn); ?>
