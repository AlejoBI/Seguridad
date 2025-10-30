# ⚡ Inicio Rápido - Escenario 2

## 🚀 Instalación en 3 Pasos

### 1️⃣ Instalar XAMPP
```
1. Descargar: https://www.apachefriends.org/
2. Instalar en: C:\xampp
3. Iniciar Apache y MySQL
```

### 2️⃣ Configurar Base de Datos
```powershell
# Abrir phpMyAdmin
http://localhost/phpmyadmin

# Crear BD "lab_seguridad" e importar:
1. database/schema.sql  (crea tablas)
2. database/data.sql    (inserta datos)
```

### 3️⃣ Desplegar Aplicación
```powershell
Copy-Item -Recurse "app_vulnerable" "C:\xampp\htdocs\lab_seguridad"
```

### ✅ Listo!
```
http://localhost/lab_seguridad
```

📖 **¿Problemas?** Ver [GUIA_INSTALACION.md](GUIA_INSTALACION.md)

---

## 🎯 Uso Básico

### Credenciales
```
admin / admin123
user / user123
```

### Probar Vulnerabilidades

**SQL Injection:**
```
' OR '1'='1
```

**XSS Reflejado:**
```
<script>alert('XSS')</script>
```

**XSS Almacenado:**
```
<img src=x onerror="alert('XSS')">
```

---

## � Análisis con OWASP ZAP

```
1. Descargar: https://www.zaproxy.org/download/
2. Quick Start → http://localhost/lab_seguridad
3. Clic "Attack" → Esperar ~15 min
4. Ver "Alerts" → ~18 vulnerabilidades
```

---

## 📚 Más Información

- 📖 **GUIA_INSTALACION.md** - Instalación detallada + solución de problemas
- 🎓 **GUIA_CLASE.md** - Presentación completa (70 min)
- � **README.md** - Descripción del proyecto

---

## ⚠️ Solo Fines Educativos
🔴 NO exponer a internet | 🔴 Solo ambiente local
