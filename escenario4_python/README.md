# 🛡️ Escenario 4 — Análisis de Vulnerabilidades con Python

## 📋 Descripción
Sistema de análisis de seguridad para código Python que detecta vulnerabilidades comunes **sin usar ZAP**.  
Permite iteración rápida: **correr → arreglar → volver a correr**.

## ✨ Características
- ✅ Detección de 9+ tipos de vulnerabilidades (OWASP Top 10)
- ✅ Análisis estático de código (sin ejecución)
- ✅ Reportes HTML visuales y JSON
- ✅ Análisis comparativo antes/después
- ✅ Reducción comprobada: **88.89%** de vulnerabilidades

## 🎯 Archivos Principales
```
escenario4_python/
├── 📖 GUIA_CLASE.md              ⭐ LEER PRIMERO - Guía completa
├── 🐍 analizador_seguridad.py    Motor de análisis
├── 📝 app_vulnerable.py          Ejemplo con 9 vulnerabilidades
├── ✅ app_corregida.py           Versión segura (1 vulnerabilidad)
├── 📦 requirements.txt           Dependencias
└── 📂 reportes/                  Reportes generados
```

## 🚀 Inicio Rápido

### 1. Instalación
```powershell
# Crear y activar entorno virtual
python -m venv venv
.\venv\Scripts\activate

# Instalar dependencias
pip install -r requirements.txt
```

### 2. Análisis Básico
```powershell
# Analizar aplicación vulnerable
python analizador_seguridad.py --target app_vulnerable.py

# Ver reporte
start reportes\reporte_app_vulnerable_*.html
```

### 3. Análisis Comparativo
```powershell
python analizador_seguridad.py --compare-mode ^
    --original app_vulnerable.py ^
    --fixed app_corregida.py ^
    --output reportes\comparativa.html

start reportes\comparativa.html
```

## 📊 Resultados Demostrados

**app_vulnerable.py:**
```
🔴 CRÍTICAS: 6
🟠 ALTAS: 1  
🟡 MEDIAS: 2
Total: 9 vulnerabilidades
```

**app_corregida.py:**
```
🔴 CRÍTICAS: 0
🟠 ALTAS: 0
🟡 MEDIAS: 1
Total: 1 vulnerabilidad

✅ Reducción: 88.89%
```

## 📚 Documentación Para Clase

**👉 Lee `GUIA_CLASE.md` para:**
- Explicación detallada de cada librería
- Funcionamiento paso a paso del analizador
- Ejemplos de código vulnerable vs corregido
- Ejercicios prácticos para estudiantes
- Comparativa con OWASP ZAP

## 🔍 Vulnerabilidades Detectadas

1. **SQL Injection** (CRITICAL)
2. **Command Injection** (CRITICAL)
3. **Hardcoded Secrets** (CRITICAL)
4. **Insecure Deserialization** (CRITICAL)
5. **Cross-Site Scripting - XSS** (HIGH)
6. **Weak Cryptography** (MEDIUM)
7. **Weak Random** (MEDIUM)
8. **Debug Mode Enabled** (MEDIUM)

## ⚡ Comandos Principales

```powershell
# Análisis simple
python analizador_seguridad.py --target app.py

# Formato JSON
python analizador_seguridad.py --target app.py --format json

# Modo verbose
python analizador_seguridad.py --target app.py --verbose

# Analizar proyecto completo
python analizar_proyecto.py ./mi_proyecto
```

## 💡 Ventajas vs OWASP ZAP

| Característica | Este Proyecto | ZAP |
|----------------|---------------|-----|
| ⚡ Velocidad | < 1 segundo | 5-10 min |
| 💾 Tamaño | ~2 MB | ~500 MB |
| 🔧 Setup | 3 minutos | 30 minutos |
| 📊 CI/CD | ✅ Fácil | ⚠️ Complejo |
| 🔍 Análisis | Estático | Dinámico |

---

**📖 Para clase: Abrir `GUIA_CLASE.md`**
