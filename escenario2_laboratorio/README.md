# 🔬 Escenario 2 — Laboratorio con OWASP ZAP

## 📖 Descripción

Sistema CRUD vulnerable para análisis dinámico con OWASP ZAP.

**Stack:** XAMPP (Apache + MySQL + PHP)

---

## 📂 Estructura

```
escenario2_laboratorio/
├── README.md                    # Este archivo
├── GUIA_INSTALACION.md         # Instalación XAMPP
├── GUIA_CLASE.md               # Guía para presentación
│
├── app_vulnerable/             # Aplicación con vulnerabilidades
│   ├── index.php
│   ├── config.php
│   ├── login.php
│   ├── usuarios.php
│   ├── productos.php
│   ├── logout.php
│   └── css/style.css
│
└── database/                   # Scripts de BD
    ├── schema.sql
    └── data.sql
```

---

## 🚨 Vulnerabilidades Incluidas

| Vulnerabilidad | Ubicación | Severidad |
|----------------|-----------|-----------|
| **SQL Injection** | login.php, usuarios.php, productos.php | 🔴 Critical |
| **XSS Reflejado** | usuarios.php (búsqueda) | 🔴 High |
| **XSS Almacenado** | productos.php (comentarios) | 🔴 High |
| **CSRF** | Todos los formularios | 🟠 Medium |
| **Broken Authentication** | config.php, login.php | 🟠 Medium |
| **Data Exposure** | usuarios.php (passwords visibles) | 🟠 Medium |
| **Broken Access Control** | productos.php (sin roles) | 🟠 Medium |
| **Misconfiguration** | config.php (debug ON) | 🟡 Low |

**Total:** 8 tipos de vulnerabilidades

---

## 🚀 Instalación Rápida

### 1. Instalar XAMPP

```
https://www.apachefriends.org/
→ Descargar Windows installer
→ Instalar en C:\xampp
→ Iniciar Apache y MySQL
```

### 2. Configurar Base de Datos

```
1. Abrir: http://localhost/phpmyadmin
2. Crear base de datos: lab_seguridad
3. Importar: database/schema.sql
4. Importar: database/data.sql
```

### 3. Desplegar Aplicación

```powershell
# Copiar archivos
Copy-Item -Recurse "app_vulnerable" "C:\xampp\htdocs\lab_seguridad"
```

### 4. Acceder

```
http://localhost/lab_seguridad
```

📖 **Detalles:** Ver [GUIA_INSTALACION.md](GUIA_INSTALACION.md)

---

## 🔍 Análisis con OWASP ZAP

### Instalar ZAP

```
https://www.zaproxy.org/download/
→ Descargar Windows installer
→ Instalar y ejecutar
```

### Ejecutar Análisis

```
1. Quick Start → URL: http://localhost/lab_seguridad
2. Clic en "Attack"
3. Esperar ~15 minutos
4. Revisar "Alerts"
5. Generar reporte HTML
```

### Resultados Esperados

```
🔴 Critical:  6 vulnerabilidades
🟠 Medium:    4 vulnerabilidades
🟡 Low:       8 vulnerabilidades
───────────────────────────────
📊 Total:     18 hallazgos
```

---

## 🎯 Credenciales de Prueba

```
Usuario: admin    Password: admin123    Rol: admin
Usuario: user     Password: user123     Rol: user
```

### Payloads para Probar

**SQL Injection (login):**
```
Usuario: ' OR '1'='1
Password: cualquier_cosa
```

**XSS (búsqueda usuarios):**
```
<script>alert('XSS')</script>
<img src=x onerror="alert(1)">
```

**XSS Almacenado (descripción producto):**
```
<img src=x onerror="alert('XSS Stored')">
```

---

## 📊 Herramientas Utilizadas

### Aplicación
- **PHP:** 8.x
- **MySQL:** 8.x
- **Apache:** 2.4.x
- **XAMPP:** Bundle completo

### Análisis
- **OWASP ZAP:** Dynamic Application Security Testing (DAST)
- **phpMyAdmin:** Gestión de BD

---

## 📚 Documentación

- **GUIA_INSTALACION.md** - Instalación paso a paso
- **GUIA_CLASE.md** - Guía para demostración (70 min)

---

## ⚠️ ADVERTENCIA

```
╔═══════════════════════════════════════╗
║  🚨 SOLO FINES EDUCATIVOS 🚨         ║
║                                       ║
║  🔴 NO EXPONER A INTERNET            ║
║  🔴 NO USAR EN PRODUCCIÓN            ║
║  🔴 SOLO AMBIENTE LOCAL              ║
║                                       ║
╚═══════════════════════════════════════╝
```

---

## 🎓 Uso en Clase

Ver **GUIA_CLASE.md** para:
- Timeline de 70 minutos
- Slides sugeridos
- Ejercicios prácticos
- Comparativas antes/después

---

## 🎉 ¡Listo!

1. ✅ Instalar XAMPP
2. ✅ Importar BD
3. ✅ Copiar archivos
4. ✅ Analizar con ZAP
5. ✅ Presentar en clase
