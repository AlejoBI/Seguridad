# 🖥️ Guía de Instalación - XAMPP (Windows)

## 📋 Tabla de Contenidos
1. [Requisitos Previos](#requisitos-previos)
2. [Descarga e Instalación de XAMPP](#descarga-e-instalación-de-xampp)
3. [Configuración de XAMPP](#configuración-de-xampp)
4. [Instalación de la Aplicación](#instalación-de-la-aplicación)
5. [Configuración de la Base de Datos](#configuración-de-la-base-de-datos)
6. [Verificación](#verificación)
7. [Solución de Problemas](#solución-de-problemas)

---

## 📌 Requisitos Previos

- **Sistema Operativo:** Windows 10/11 (64-bit)
- **Espacio en Disco:** Mínimo 1 GB libre
- **RAM:** Mínimo 2 GB
- **Permisos:** Acceso de administrador

---

## 📥 Descarga e Instalación de XAMPP

### Paso 1: Descargar XAMPP

1. Visita: https://www.apachefriends.org/
2. Descarga **XAMPP para Windows** (versión 8.2.x o superior)
3. El archivo será aproximadamente 150 MB

### Paso 2: Ejecutar el Instalador

1. **Ejecutar como Administrador:**
   ```
   Clic derecho en xampp-windows-x64-X.X.X-installer.exe
   → "Ejecutar como administrador"
   ```

2. **Componentes a Instalar:**
   - ✅ Apache
   - ✅ MySQL
   - ✅ PHP
   - ✅ phpMyAdmin
   - ❌ FileZilla (opcional)
   - ❌ Mercury (opcional)
   - ❌ Tomcat (opcional)

3. **Directorio de Instalación:**
   ```
   C:\xampp
   ```
   ⚠️ **Importante:** No instalar en `Program Files` (puede causar problemas de permisos)

4. **Completar Instalación:**
   - Clic en "Next" → "Next" → "Install"
   - Esperar 5-10 minutos
   - Desmarcar "Learn more about Bitnami"
   - Clic en "Finish"

### Paso 3: Configurar el Firewall

Si aparece el firewall de Windows:
- ✅ Marcar "Redes privadas"
- ✅ Clic en "Permitir acceso"

---

## ⚙️ Configuración de XAMPP

### Paso 1: Iniciar el Panel de Control

1. Abrir **XAMPP Control Panel** como administrador
2. Puede estar en: `C:\xampp\xampp-control.exe`

### Paso 2: Iniciar Servicios

1. **Iniciar Apache:**
   - Clic en "Start" junto a Apache
   - El texto debe cambiar a verde: "Running"
   
2. **Iniciar MySQL:**
   - Clic en "Start" junto a MySQL
   - El texto debe cambiar a verde: "Running"

3. **Verificar Puertos:**
   - Apache debe usar puerto **80** (HTTP) y **443** (HTTPS)
   - MySQL debe usar puerto **3306**

### Paso 3: Configurar Apache (Opcional)

Si el puerto 80 está ocupado:

1. Clic en "Config" (Apache) → "httpd.conf"
2. Buscar: `Listen 80`
3. Cambiar a: `Listen 8080`
4. Guardar y reiniciar Apache

---

## 📦 Instalación de la Aplicación

### Paso 1: Copiar Archivos

1. **Ubicación de archivos web:**
   ```
   C:\xampp\htdocs\
   ```

2. **Copiar la carpeta app_vulnerable:**
   ```powershell
   # Desde PowerShell
   Copy-Item -Recurse "app_vulnerable" "C:\xampp\htdocs\lab_seguridad"
   ```
   
   O manualmente:
   - Copiar la carpeta `app_vulnerable`
   - Pegar en `C:\xampp\htdocs`
   - Renombrar a `lab_seguridad`

3. **Estructura final:**
   ```
   C:\xampp\htdocs\lab_seguridad\
   ├── index.php
   ├── config.php
   ├── login.php
   ├── usuarios.php
   ├── productos.php
   ├── logout.php
   └── css\
       └── style.css
   ```

### Paso 2: Verificar Permisos

Asegurarse que los archivos sean accesibles:
```powershell
# En PowerShell como Administrador
icacls "C:\xampp\htdocs\lab_seguridad" /grant Everyone:F /T
```

---

## 🗄️ Configuración de la Base de Datos

### Método 1: Usando phpMyAdmin (Recomendado)

1. **Abrir phpMyAdmin:**
   ```
   http://localhost/phpmyadmin
   ```

2. **Crear la Base de Datos:**
   - Clic en "Nueva" en el panel izquierdo
   - Nombre: `lab_seguridad`
   - Cotejamiento: `utf8mb4_unicode_ci`
   - Clic en "Crear"

3. **Importar Schema:**
   - Seleccionar la base de datos `lab_seguridad`
   - Clic en la pestaña "Importar"
   - Clic en "Seleccionar archivo"
   - Seleccionar: `database/schema.sql`
   - Clic en "Continuar"

4. **Importar Datos:**
   - Mantenerse en `lab_seguridad`
   - Clic en "Importar" nuevamente
   - Seleccionar: `database/data.sql`
   - Clic en "Continuar"

5. **Verificar Tablas:**
   ```
   Deberías ver:
   - usuarios (5 registros)
   - productos (8 registros)
   - comentarios (6 registros)
   - sesiones (0 registros)
   ```

### Método 2: Usando MySQL Command Line

1. **Abrir MySQL Shell:**
   ```powershell
   cd C:\xampp\mysql\bin
   .\mysql.exe -u root -p
   ```
   (Presionar Enter cuando pida password, está vacío por defecto)

2. **Ejecutar Scripts:**
   ```sql
   source C:/xampp/htdocs/lab_seguridad/database/schema.sql;
   source C:/xampp/htdocs/lab_seguridad/database/data.sql;
   
   -- Verificar
   USE lab_seguridad;
   SHOW TABLES;
   SELECT COUNT(*) FROM usuarios;
   SELECT COUNT(*) FROM productos;
   ```

---

## ✅ Verificación

### Paso 1: Verificar Apache y MySQL

En el XAMPP Control Panel:
- ✅ Apache debe estar en verde "Running"
- ✅ MySQL debe estar en verde "Running"

### Paso 2: Probar la Aplicación

1. **Abrir navegador:**
   ```
   http://localhost/lab_seguridad
   ```

2. **Deberías ver:**
   - Página de inicio con el título "Sistema CRUD - Lab Seguridad"
   - 3 tarjetas de características
   - Advertencia de vulnerabilidades
   - Botones funcionando

3. **Probar Login:**
   ```
   http://localhost/lab_seguridad/login.php
   
   Usuario: admin
   Password: admin123
   ```

4. **Probar SQL Injection:**
   - En login, usuario: `' OR '1'='1`
   - Password: cualquier cosa
   - Debe iniciar sesión sin credenciales válidas

### Paso 3: Verificar Base de Datos

```
http://localhost/phpmyadmin
→ lab_seguridad
→ Verificar que las 4 tablas existan
```

---

## 🔧 Solución de Problemas

### Problema 1: Puerto 80 Ocupado

**Error:** "Apache no inicia, puerto 80 en uso"

**Solución:**
1. Verificar qué usa el puerto:
   ```powershell
   netstat -ano | findstr :80
   ```

2. Opciones:
   - **A)** Cambiar puerto de Apache (ver Paso 3 de Configuración)
   - **B)** Detener el servicio que usa el puerto:
     ```powershell
     # Si es IIS:
     net stop was /y
     net stop w3svc
     ```

### Problema 2: MySQL No Inicia

**Error:** "MySQL no inicia, error en logs"

**Solución:**
1. Verificar logs:
   ```
   C:\xampp\mysql\data\mysql_error.log
   ```

2. Limpiar archivos temporales:
   - Detener XAMPP completamente
   - Eliminar: `C:\xampp\mysql\data\ibdata1`
   - Reiniciar XAMPP

### Problema 3: Error 403 Forbidden

**Error:** "403 Forbidden - No tienes permiso para acceder"

**Solución:**
```powershell
# Dar permisos completos
icacls "C:\xampp\htdocs\lab_seguridad" /grant Everyone:F /T
```

### Problema 4: Error de Conexión PHP-MySQL

**Error:** "Cannot connect to database"

**Verificar en config.php:**
```php
define('DB_HOST', 'localhost');  // ✅
define('DB_USER', 'root');       // ✅
define('DB_PASS', '');           // ✅ (vacío por defecto)
define('DB_NAME', 'lab_seguridad'); // ✅
```

### Problema 5: CSS No Carga

**Error:** "La página se ve sin estilos"

**Verificar:**
1. Ruta del archivo CSS:
   ```
   C:\xampp\htdocs\lab_seguridad\css\style.css
   ```

2. En el navegador:
   ```
   http://localhost/lab_seguridad/css/style.css
   ```
   Debe mostrar el contenido CSS

---

## 🎯 Comandos Útiles

### Iniciar/Detener Servicios (PowerShell)

```powershell
# Iniciar Apache
C:\xampp\apache\bin\httpd.exe

# Detener Apache
taskkill /F /IM httpd.exe

# Iniciar MySQL
C:\xampp\mysql\bin\mysqld.exe

# Detener MySQL
C:\xampp\mysql\bin\mysqladmin.exe -u root shutdown
```

### Verificar Estado

```powershell
# Ver procesos de Apache
Get-Process | Where-Object {$_.Name -eq "httpd"}

# Ver procesos de MySQL
Get-Process | Where-Object {$_.Name -eq "mysqld"}
```

---

## 📚 Recursos Adicionales

- **Documentación XAMPP:** https://www.apachefriends.org/docs/
- **Foro XAMPP:** https://community.apachefriends.org/
- **PHP Manual:** https://www.php.net/manual/es/

---

## ⚠️ Advertencia de Seguridad

**Esta instalación es INTENCIONALMENTE VULNERABLE para fines educativos.**

🔴 **NO EXPONER A INTERNET**
🔴 **NO USAR EN PRODUCCIÓN**
🔴 **SOLO EN AMBIENTE LOCAL CONTROLADO**

---

## 🎉 ¡Listo!

Si todos los pasos funcionaron correctamente:

✅ XAMPP instalado y corriendo
✅ Apache funcionando en puerto 80
✅ MySQL funcionando en puerto 3306
✅ Base de datos creada e importada
✅ Aplicación accesible en http://localhost/lab_seguridad

**Siguiente paso:** [GUIA_ANALISIS_ZAP.md](GUIA_ANALISIS_ZAP.md) - Analizar con OWASP ZAP
