-- Datos de prueba para Laboratorio de Seguridad
-- Escenario 2 - OWASP ZAP

USE lab_seguridad;

-- Insertar usuarios de prueba
-- VULNERABILIDAD: Contraseñas en texto plano (intencionalmente vulnerable)
INSERT INTO usuarios (username, email, password, role) VALUES
('admin', 'admin@lab.local', 'admin123', 'admin'),
('user', 'user@lab.local', 'user123', 'user'),
('test', 'test@lab.local', 'test123', 'user'),
('juan', 'juan@lab.local', 'password', 'user'),
('maria', 'maria@lab.local', '123456', 'user');

-- Insertar productos de prueba
INSERT INTO productos (nombre, descripcion, precio, categoria) VALUES
('Laptop Dell XPS 13', 'Laptop ultraportátil con procesador Intel i7', 1299.99, 'Computadoras'),
('iPhone 14 Pro', 'Smartphone de última generación', 999.99, 'Móviles'),
('Samsung Galaxy S23', 'Teléfono Android premium', 899.99, 'Móviles'),
('MacBook Pro M2', 'Computadora portátil para profesionales', 1999.99, 'Computadoras'),
('iPad Air', 'Tablet versátil para trabajo y entretenimiento', 599.99, 'Tablets'),
('Sony WH-1000XM5', 'Auriculares con cancelación de ruido', 399.99, 'Audio'),
('Monitor LG 27" 4K', 'Monitor UHD para diseño gráfico', 499.99, 'Monitores'),
('Teclado Mecánico Keychron', 'Teclado mecánico retroiluminado', 89.99, 'Accesorios');

-- Insertar comentarios de prueba
INSERT INTO comentarios (producto_id, usuario, comentario) VALUES
(1, 'admin', 'Excelente producto, muy recomendado'),
(1, 'user', 'La mejor laptop que he tenido'),
(2, 'maria', 'La cámara es increíble!'),
(3, 'juan', 'Buen teléfono, pero un poco caro'),
(4, 'test', 'Rendimiento excepcional'),
(5, 'admin', 'Perfecta para leer y trabajar');

-- Comentario vulnerable con XSS (para demostración)
-- INSERT INTO comentarios (producto_id, usuario, comentario) VALUES
-- (1, 'hacker', '<script>alert("XSS Vulnerability!")</script>');

-- Verificar datos insertados
SELECT 'Usuarios insertados:' as Info, COUNT(*) as Total FROM usuarios;
SELECT 'Productos insertados:' as Info, COUNT(*) as Total FROM productos;
SELECT 'Comentarios insertados:' as Info, COUNT(*) as Total FROM comentarios;

-- Mostrar estructura de tablas
SHOW TABLES;
