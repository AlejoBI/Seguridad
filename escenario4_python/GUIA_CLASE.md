# 📚 GUÍA PARA CLASE - Análisis de Vulnerabilidades con Python

## 🎯 Objetivo del Escenario 4

Analizar vulnerabilidades en aplicaciones Python utilizando **librerías nativas de Python** sin depender de herramientas externas como OWASP ZAP.

---

## 📦 LIBRERÍAS UTILIZADAS Y SU PROPÓSITO

### 1. **Flask (Framework Web)**
```python
from flask import Flask, request, render_template_string
```

**¿Qué es?**
- Framework web ligero para Python
- Usado para crear las aplicaciones de ejemplo (vulnerable y corregida)

**¿Por qué se usa?**
- Simular una aplicación web real
- Demostrar vulnerabilidades comunes en aplicaciones web
- **Versión:** 3.0.0

---

### 2. **Bandit (Análisis de Seguridad)**
```bash
pip install bandit==1.7.5
```

**¿Qué es?**
- Herramienta de análisis estático de seguridad para Python
- Encuentra vulnerabilidades comunes en código Python

**¿Qué detecta?**
- Hardcoded passwords
- SQL injection patterns
- Weak cryptography (MD5, SHA1)
- Unsafe deserialization (pickle)
- Insecure random number generation

**Uso:**
```bash
bandit -r . -f json -o bandit_report.json
```

---

### 3. **Safety (Verificación de CVEs)**
```bash
pip install safety==3.0.1
```

**¿Qué es?**
- Verifica dependencias contra bases de datos de vulnerabilidades conocidas
- Consulta CVE (Common Vulnerabilities and Exposures)

**¿Qué detecta?**
- Versiones vulnerables de librerías instaladas
- CVEs conocidos en dependencias

**Uso:**
```bash
safety check
```

---

### 4. **Pylint (Análisis de Calidad)**
```bash
pip install pylint==3.0.3
```

**¿Qué es?**
- Analizador de calidad de código Python
- Detecta errores de programación y problemas de seguridad

**¿Qué detecta?**
- Código no seguro
- Malas prácticas
- Errores potenciales

---

### 5. **Semgrep (Análisis Semántico)**
```bash
pip install semgrep==1.45.0
```

**¿Qué es?**
- Motor de análisis de código que usa patrones semánticos
- Similar a grep pero entiende la estructura del código

**¿Qué detecta?**
- Patrones complejos de vulnerabilidades
- Análisis contextual del código
- Reglas personalizadas de seguridad

---

### 6. **Jinja2 (Motor de Templates)**
```bash
pip install jinja2==3.1.2
```

**¿Qué es?**
- Motor de plantillas para Python
- Usado en Flask para renderizar HTML

**Relevancia de seguridad:**
- Previene XSS con autoescaping
- Usado en la aplicación corregida

---

### 7. **Otras Librerías de Soporte**

```bash
markdown==3.5.1      # Generación de documentación
pygments==2.17.2     # Sintaxis coloreada en reportes
colorama==0.4.6      # Colores en terminal
tabulate==0.9.0      # Tablas formateadas
```

---

## 🔍 CÓMO FUNCIONA EL ANALIZADOR

### Arquitectura del Sistema

```
┌─────────────────────────────────────────────────────────┐
│                  ANALIZADOR_SEGURIDAD.PY                │
└─────────────────────────────────────────────────────────┘
                            │
                            ├── SecurityAnalyzer
                            │   ├── check_hardcoded_secrets()
                            │   ├── check_sql_injection()
                            │   ├── check_command_injection()
                            │   ├── check_path_traversal()
                            │   ├── check_xss()
                            │   ├── check_weak_crypto()
                            │   ├── check_insecure_deserialization()
                            │   ├── check_csrf()
                            │   ├── check_weak_random()
                            │   ├── check_debug_mode()
                            │   ├── check_open_redirect()
                            │   └── check_eval_injection()
                            │
                            ├── ReportGenerator
                            │   ├── generate_html()
                            │   ├── generate_json()
                            │   └── print_console_summary()
                            │
                            └── ComparativeAnalyzer
                                ├── compare()
                                └── generate_comparative_report()
```

---

## 🛠️ FUNCIONAMIENTO PASO A PASO

### **Paso 1: Carga del Archivo**
```python
def load_file(self):
    with open(self.target_file, 'r', encoding='utf-8') as f:
        self.source_code = f.read()
        self.lines = self.source_code.split('\n')
```

**¿Qué hace?**
- Lee el archivo Python completo
- Divide el código en líneas individuales para análisis

---

### **Paso 2: Análisis con Expresiones Regulares**

Cada tipo de vulnerabilidad se busca con patrones específicos:

#### **Ejemplo 1: SQL Injection**
```python
def check_sql_injection(self):
    patterns = [
        r'execute\([^)]*f["\'].*\{.*\}',  # f-strings en SQL
        r'execute\([^)]*%.*%',             # % formatting
        r'execute\([^)]*\+',               # concatenación
    ]
    
    for line_num, line in enumerate(self.lines, 1):
        for pattern in patterns:
            if re.search(pattern, line):
                # ¡Vulnerabilidad encontrada!
                self.add_vulnerability(...)
```

**Código vulnerable detectado:**
```python
query = f"SELECT * FROM users WHERE id = '{user_id}'"
cursor.execute(query)  # ❌ VULNERABLE
```

**Código seguro:**
```python
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))  # ✅ SEGURO
```

---

#### **Ejemplo 2: XSS (Cross-Site Scripting)**
```python
def check_xss(self):
    patterns = [
        r'render_template_string\([^)]*f["\']',  # f-string en template
        r'<.*\{.*\}.*>',                         # HTML con variables
    ]
```

**Código vulnerable:**
```python
return f"<h1>Hola {username}</h1>"  # ❌ VULNERABLE a XSS
```

**Código seguro:**
```python
return render_template_string("<h1>Hola {{ username|e }}</h1>")  # ✅ SEGURO
```

---

#### **Ejemplo 3: Hardcoded Secrets**
```python
def check_hardcoded_secrets(self):
    patterns = [
        (r'SECRET_KEY\s*=\s*["\'](.+?)["\']', "Secret Key"),
        (r'PASSWORD\s*=\s*["\'](.+?)["\']', "Password"),
        (r'API_KEY\s*=\s*["\'](.+?)["\']', "API Key"),
    ]
```

**Código vulnerable:**
```python
API_KEY = "sk-1234567890abcdef"  # ❌ VULNERABLE
```

**Código seguro:**
```python
API_KEY = os.environ.get('API_KEY')  # ✅ SEGURO
```

---

#### **Ejemplo 4: Command Injection**
```python
def check_command_injection(self):
    dangerous_funcs = ['os.system', 'os.popen', 'subprocess.call']
    
    for line_num, line in enumerate(self.lines, 1):
        for func in dangerous_funcs:
            if func in line and ('f"' in line or '+' in line):
                # Detecta concatenación de comandos
                self.add_vulnerability(...)
```

**Código vulnerable:**
```python
os.system(f"ping {host}")  # ❌ VULNERABLE
```

**Código seguro:**
```python
subprocess.run(['ping', '-n', '1', host], timeout=5)  # ✅ SEGURO
```

---

### **Paso 3: Clasificación por Severidad**

```python
class Severity(Enum):
    CRITICAL = "CRITICAL"  # 🔴 Explotación inmediata, alto impacto
    HIGH = "HIGH"          # 🟠 Explotación probable, impacto significativo
    MEDIUM = "MEDIUM"      # 🟡 Explotación posible, impacto moderado
    LOW = "LOW"            # 🔵 Bajo riesgo, mejor práctica
```

**Criterios de clasificación:**

| Vulnerabilidad | Severidad | ¿Por qué? |
|----------------|-----------|-----------|
| SQL Injection | CRITICAL | Acceso a base de datos |
| Command Injection | CRITICAL | Ejecución de código del sistema |
| Hardcoded Secrets | CRITICAL | Credenciales expuestas |
| XSS | HIGH | Robo de sesiones, phishing |
| Path Traversal | HIGH | Acceso a archivos del sistema |
| CSRF | HIGH | Acciones no autorizadas |
| Weak Random | MEDIUM | Tokens predecibles |
| Debug Mode | MEDIUM | Información sensible expuesta |

---

### **Paso 4: Generación de Reportes**

#### **Formato HTML**
```python
def generate_html(self, output_file: str):
    html = f"""
    <!DOCTYPE html>
    <html>
        <head><title>Reporte de Seguridad</title></head>
        <body>
            <h1>Vulnerabilidades Encontradas: {len(self.vulnerabilities)}</h1>
            <!-- Cada vulnerabilidad con su código, línea, recomendación -->
        </body>
    </html>
    """
```

**Incluye:**
- Código vulnerable exacto
- Número de línea
- Descripción del problema
- Referencia OWASP y CWE
- Recomendación de corrección

---

#### **Formato JSON**
```json
{
  "metadata": {
    "total_vulnerabilities": 9,
    "statistics": {
      "CRITICAL": 6,
      "HIGH": 1,
      "MEDIUM": 2
    }
  },
  "vulnerabilities": [
    {
      "id": "SEC-001-42",
      "title": "SQL Injection",
      "severity": "CRITICAL",
      "line": 42,
      "code": "cursor.execute(f\"SELECT * FROM users WHERE id = '{user_id}'\")",
      "recommendation": "Usar parámetros preparados"
    }
  ]
}
```

---

## 🎓 DEMOSTRACIÓN EN CLASE

### **1. Instalación (3 minutos)**
```bash
# Crear entorno virtual
python -m venv venv

# Activar
.\venv\Scripts\activate

# Instalar dependencias
pip install -r requirements.txt
```

---

### **2. Análisis de Aplicación Vulnerable**
```bash
python analizador_seguridad.py --target app_vulnerable.py
```

**Resultado esperado:**
```
🔍 Analizando: app_vulnerable.py

📊 RESUMEN DEL ANÁLISIS
════════════════════════════════════════
Vulnerabilidades encontradas: 9
  🔴 CRÍTICAS: 6
  🟠 ALTAS: 1
  🟡 MEDIAS: 2
════════════════════════════════════════

✓ Reporte generado: reportes/reporte_app_vulnerable.html
```

---

### **3. Revisar el Reporte HTML**
```bash
start reportes\reporte_app_vulnerable_*.html
```

**Mostrar en clase:**
- Las 9 vulnerabilidades detectadas
- Código vulnerable exacto
- Explicación de cada problema
- Recomendaciones específicas

---

### **4. Análisis de Aplicación Corregida**
```bash
python analizador_seguridad.py --target app_corregida.py
```

**Resultado esperado:**
```
📊 RESUMEN DEL ANÁLISIS
════════════════════════════════════════
Vulnerabilidades encontradas: 1
  🔴 CRÍTICAS: 0
  🟠 ALTAS: 0
  🟡 MEDIAS: 1
════════════════════════════════════════
```

---

### **5. Análisis Comparativo**
```bash
python analizador_seguridad.py --compare-mode \
    --original app_vulnerable.py \
    --fixed app_corregida.py \
    --output reportes/comparativa.html
```

**Resultado esperado:**
```
✅ Reducción de vulnerabilidades: 88.89%
   Original: 9 → Corregido: 1
```

---

## 📊 COMPARATIVA: Antes vs Después

### **app_vulnerable.py (Original)**

| Vulnerabilidad | Línea | Código |
|----------------|-------|--------|
| Hardcoded Secret | 16 | `SECRET_KEY = "mi_clave_super_secreta_123"` |
| SQL Injection | 25 | `query = f"SELECT * FROM users WHERE username = '{username}'"` |
| Command Injection | 35 | `os.system(f"ping -n 1 {host}")` |
| XSS | 48 | `html = f"<h1>Resultados para: {query}</h1>"` |
| Weak Crypto | 21 | `hashlib.md5(password.encode()).hexdigest()` |
| Insecure Pickle | 62 | `obj = pickle.loads(data)` |

---

### **app_corregida.py (Corregida)**

| Vulnerabilidad | Solución Aplicada |
|----------------|-------------------|
| Hardcoded Secret | `SECRET_KEY = os.environ.get('SECRET_KEY')` |
| SQL Injection | `cursor.execute(query, (username,))` |
| Command Injection | `subprocess.run(['ping', '-n', '1', host])` |
| XSS | `render_template_string("{{ query\|e }}")` |
| Weak Crypto | `hashlib.pbkdf2_hmac('sha256', password, salt, 100000)` |
| Insecure Pickle | `data = json.loads(request.data)` |

---

## 💡 VENTAJAS DE ESTE ENFOQUE

### **vs OWASP ZAP**

| Característica | Python Analyzer | OWASP ZAP |
|----------------|-----------------|-----------|
| Velocidad | < 1 segundo | 5-10 minutos |
| Instalación | `pip install` | ~500 MB, Java |
| Análisis estático | ✅ Sí | ❌ No |
| Offline | ✅ Sí | ⚠️ Limitado |
| Integración CI/CD | ✅ Fácil | ⚠️ Complejo |
| Curva de aprendizaje | ✅ Baja | ⚠️ Alta |

---

## 🎯 PUNTOS CLAVE PARA LA CLASE

### **1. Análisis Estático vs Dinámico**

**Análisis Estático (este proyecto):**
- ✅ Examina código sin ejecutarlo
- ✅ Rápido y eficiente
- ⚠️ No detecta problemas de runtime

**Análisis Dinámico (ZAP):**
- ✅ Prueba la aplicación en ejecución
- ✅ Detecta problemas de runtime
- ⚠️ Más lento y complejo

---

### **2. Importancia de las Expresiones Regulares**

Las regex son fundamentales para detectar patrones:
```python
# Detectar SQL Injection
pattern = r'execute\([^)]*f["\'].*\{.*\}'

# Detectar hardcoded secrets
pattern = r'API_KEY\s*=\s*["\'](.+?)["\']'
```

---

### **3. Ciclo de Mejora Continua**

```
1. Desarrollar código
   ↓
2. Analizar con herramienta
   ↓
3. Revisar vulnerabilidades
   ↓
4. Aplicar correcciones
   ↓
5. Re-analizar
   ↓
6. Repetir hasta 0 críticas
```

---

## 🎬 CONCLUSIÓN

Este proyecto demuestra cómo:
- ✅ Analizar código Python sin herramientas externas
- ✅ Detectar vulnerabilidades comunes (OWASP Top 10)
- ✅ Generar reportes profesionales
- ✅ Aplicar correcciones efectivas
- ✅ Medir mejoras con análisis comparativo

**Resultado:** Reducción de 88.89% en vulnerabilidades (9 → 1)
