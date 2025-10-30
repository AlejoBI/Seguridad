"""
Analizador de Seguridad para Código Python
Detecta vulnerabilidades comunes sin necesidad de herramientas externas como ZAP
"""

import os
import re
import ast
import json
import argparse
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

class Severity(Enum):
    """Niveles de severidad de vulnerabilidades"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class Vulnerability:
    """Clase para representar una vulnerabilidad encontrada"""
    id: str
    title: str
    severity: str
    description: str
    file: str
    line: int
    code: str
    cwe: str
    owasp: str
    recommendation: str
    
    def to_dict(self):
        return asdict(self)

class SecurityAnalyzer:
    """Analizador de seguridad para código Python"""
    
    def __init__(self, target_file: str, verbose: bool = False):
        self.target_file = target_file
        self.verbose = verbose
        self.vulnerabilities: List[Vulnerability] = []
        self.source_code = ""
        self.lines = []
        
    def load_file(self):
        """Carga el archivo objetivo"""
        try:
            with open(self.target_file, 'r', encoding='utf-8') as f:
                self.source_code = f.read()
                self.lines = self.source_code.split('\n')
            if self.verbose:
                print(f"✓ Archivo cargado: {self.target_file} ({len(self.lines)} líneas)")
        except Exception as e:
            print(f"✗ Error al cargar archivo: {e}")
            raise
    
    def analyze(self):
        """Ejecuta todos los análisis de seguridad"""
        print(f"\n🔍 Analizando: {self.target_file}\n")
        
        self.load_file()
        
        # Ejecutar todos los checks
        self.check_hardcoded_secrets()
        self.check_sql_injection()
        self.check_command_injection()
        self.check_path_traversal()
        self.check_xss()
        self.check_weak_crypto()
        self.check_insecure_deserialization()
        self.check_csrf()
        self.check_weak_random()
        self.check_debug_mode()
        self.check_open_redirect()
        self.check_eval_injection()
        self.check_unsafe_imports()
        
        return self.vulnerabilities
    
    def add_vulnerability(self, vuln: Vulnerability):
        """Añade una vulnerabilidad a la lista"""
        self.vulnerabilities.append(vuln)
        if self.verbose:
            print(f"  [{vuln.severity}] {vuln.title} en línea {vuln.line}")
    
    def check_hardcoded_secrets(self):
        """Detecta credenciales y secretos hardcoded"""
        patterns = [
            (r'SECRET_KEY\s*=\s*["\'](.+?)["\']', "Secret Key Hardcoded"),
            (r'PASSWORD\s*=\s*["\'](.+?)["\']', "Password Hardcoded"),
            (r'API_KEY\s*=\s*["\'](.+?)["\']', "API Key Hardcoded"),
            (r'TOKEN\s*=\s*["\'](.+?)["\']', "Token Hardcoded"),
            (r'aws_secret_access_key\s*=\s*["\'](.+?)["\']', "AWS Secret Hardcoded"),
        ]
        
        for line_num, line in enumerate(self.lines, 1):
            for pattern, title in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self.add_vulnerability(Vulnerability(
                        id=f"SEC-001-{line_num}",
                        title=title,
                        severity=Severity.CRITICAL.value,
                        description="Credenciales o secretos están hardcoded en el código fuente",
                        file=self.target_file,
                        line=line_num,
                        code=line.strip(),
                        cwe="CWE-798",
                        owasp="A02:2021 – Cryptographic Failures",
                        recommendation="Usar variables de entorno (os.environ.get()) o gestores de secretos"
                    ))
    
    def check_sql_injection(self):
        """Detecta vulnerabilidades de SQL Injection"""
        patterns = [
            r'execute\([^)]*f["\'].*\{.*\}',  # f-strings en execute
            r'execute\([^)]*%.*%',  # string formatting
            r'execute\([^)]*\+',  # concatenación
        ]
        
        for line_num, line in enumerate(self.lines, 1):
            for pattern in patterns:
                if re.search(pattern, line):
                    self.add_vulnerability(Vulnerability(
                        id=f"SEC-002-{line_num}",
                        title="SQL Injection",
                        severity=Severity.CRITICAL.value,
                        description="Consulta SQL construida con concatenación de strings sin sanitización",
                        file=self.target_file,
                        line=line_num,
                        code=line.strip(),
                        cwe="CWE-89",
                        owasp="A03:2021 – Injection",
                        recommendation="Usar parámetros preparados: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
                    ))
    
    def check_command_injection(self):
        """Detecta Command Injection"""
        dangerous_funcs = ['os.system', 'os.popen', 'subprocess.call', 'eval', 'exec']
        
        for line_num, line in enumerate(self.lines, 1):
            for func in dangerous_funcs:
                if func in line and ('f"' in line or "f'" in line or '+' in line):
                    self.add_vulnerability(Vulnerability(
                        id=f"SEC-003-{line_num}",
                        title="Command Injection",
                        severity=Severity.CRITICAL.value,
                        description=f"Ejecución de comando del sistema usando {func} con input no sanitizado",
                        file=self.target_file,
                        line=line_num,
                        code=line.strip(),
                        cwe="CWE-78",
                        owasp="A03:2021 – Injection",
                        recommendation="Validar y sanitizar inputs, usar subprocess con lista de argumentos"
                    ))
    
    def check_path_traversal(self):
        """Detecta Path Traversal"""
        patterns = [
            r'send_file\([^)]*\{',
            r'open\([^)]*\{',
            r'Path\([^)]*\{',
        ]
        
        for line_num, line in enumerate(self.lines, 1):
            for pattern in patterns:
                if re.search(pattern, line) and 'request' in line:
                    self.add_vulnerability(Vulnerability(
                        id=f"SEC-004-{line_num}",
                        title="Path Traversal",
                        severity=Severity.HIGH.value,
                        description="Acceso a archivos usando rutas sin validación, permite '../' attacks",
                        file=self.target_file,
                        line=line_num,
                        code=line.strip(),
                        cwe="CWE-22",
                        owasp="A01:2021 – Broken Access Control",
                        recommendation="Usar secure_filename() y validar que la ruta está dentro del directorio permitido"
                    ))
    
    def check_xss(self):
        """Detecta vulnerabilidades XSS"""
        patterns = [
            r'render_template_string\([^)]*f["\']',
            r'<.*\{.*\}.*>',
        ]
        
        for line_num, line in enumerate(self.lines, 1):
            for pattern in patterns:
                if re.search(pattern, line) and 'request' in self.lines[max(0, line_num-5):line_num+5]:
                    self.add_vulnerability(Vulnerability(
                        id=f"SEC-005-{line_num}",
                        title="Cross-Site Scripting (XSS)",
                        severity=Severity.HIGH.value,
                        description="Renderizado de HTML con input del usuario sin escapar",
                        file=self.target_file,
                        line=line_num,
                        code=line.strip(),
                        cwe="CWE-79",
                        owasp="A03:2021 – Injection",
                        recommendation="Usar templates con autoescaping o filtro |e en Jinja2"
                    ))
    
    def check_weak_crypto(self):
        """Detecta uso de criptografía débil"""
        weak_algos = ['md5', 'sha1', 'des', 'rc4']
        
        for line_num, line in enumerate(self.lines, 1):
            for algo in weak_algos:
                if algo in line.lower() and 'hashlib' in line:
                    self.add_vulnerability(Vulnerability(
                        id=f"SEC-006-{line_num}",
                        title="Weak Cryptography",
                        severity=Severity.HIGH.value,
                        description=f"Uso de algoritmo criptográfico débil: {algo.upper()}",
                        file=self.target_file,
                        line=line_num,
                        code=line.strip(),
                        cwe="CWE-327",
                        owasp="A02:2021 – Cryptographic Failures",
                        recommendation="Usar SHA-256, bcrypt o Argon2 para passwords"
                    ))
    
    def check_insecure_deserialization(self):
        """Detecta deserialización insegura"""
        if 'pickle.loads' in self.source_code or 'pickle.load' in self.source_code:
            for line_num, line in enumerate(self.lines, 1):
                if 'pickle.load' in line:
                    self.add_vulnerability(Vulnerability(
                        id=f"SEC-007-{line_num}",
                        title="Insecure Deserialization",
                        severity=Severity.CRITICAL.value,
                        description="Uso de pickle para deserializar datos sin validación",
                        file=self.target_file,
                        line=line_num,
                        code=line.strip(),
                        cwe="CWE-502",
                        owasp="A08:2021 – Software and Data Integrity Failures",
                        recommendation="Usar JSON en lugar de pickle, validar estructura de datos"
                    ))
    
    def check_csrf(self):
        """Detecta falta de protección CSRF"""
        routes_post = []
        for line_num, line in enumerate(self.lines, 1):
            if "methods=['POST']" in line or 'methods=["POST"]' in line:
                routes_post.append(line_num)
        
        for route_line in routes_post:
            # Buscar en las siguientes 20 líneas si hay verificación CSRF
            context = '\n'.join(self.lines[route_line:route_line+20])
            if 'csrf' not in context.lower():
                self.add_vulnerability(Vulnerability(
                    id=f"SEC-008-{route_line}",
                    title="Missing CSRF Protection",
                    severity=Severity.HIGH.value,
                    description="Endpoint POST sin validación de token CSRF",
                    file=self.target_file,
                    line=route_line,
                    code=self.lines[route_line-1].strip(),
                    cwe="CWE-352",
                    owasp="A01:2021 – Broken Access Control",
                    recommendation="Implementar verificación de token CSRF en formularios"
                ))
    
    def check_weak_random(self):
        """Detecta uso de generador de números aleatorios débil"""
        for line_num, line in enumerate(self.lines, 1):
            if 'random.randint' in line or 'random.choice' in line:
                # Verificar si es para seguridad (token, password, etc)
                context = ' '.join(self.lines[max(0, line_num-3):min(len(self.lines), line_num+3)])
                if any(word in context.lower() for word in ['token', 'password', 'secret', 'key']):
                    self.add_vulnerability(Vulnerability(
                        id=f"SEC-009-{line_num}",
                        title="Weak Random Number Generator",
                        severity=Severity.MEDIUM.value,
                        description="Uso de random() para generar valores de seguridad",
                        file=self.target_file,
                        line=line_num,
                        code=line.strip(),
                        cwe="CWE-338",
                        owasp="A02:2021 – Cryptographic Failures",
                        recommendation="Usar secrets.token_hex() o secrets.token_urlsafe() para valores criptográficos"
                    ))
    
    def check_debug_mode(self):
        """Detecta debug mode habilitado"""
        for line_num, line in enumerate(self.lines, 1):
            if 'debug=True' in line and 'app.run' in line:
                self.add_vulnerability(Vulnerability(
                    id=f"SEC-010-{line_num}",
                    title="Debug Mode Enabled",
                    severity=Severity.MEDIUM.value,
                    description="Modo debug habilitado, expone información sensible",
                    file=self.target_file,
                    line=line_num,
                    code=line.strip(),
                    cwe="CWE-489",
                    owasp="A05:2021 – Security Misconfiguration",
                    recommendation="Usar debug=False en producción o leer de variable de entorno"
                ))
    
    def check_open_redirect(self):
        """Detecta Open Redirect"""
        for line_num, line in enumerate(self.lines, 1):
            if 'redirect(' in line and 'request' in line:
                # Verificar si hay validación en líneas anteriores
                context = '\n'.join(self.lines[max(0, line_num-10):line_num])
                if 'urlparse' not in context and 'allowed' not in context.lower():
                    self.add_vulnerability(Vulnerability(
                        id=f"SEC-011-{line_num}",
                        title="Open Redirect",
                        severity=Severity.MEDIUM.value,
                        description="Redirección sin validación de URL destino",
                        file=self.target_file,
                        line=line_num,
                        code=line.strip(),
                        cwe="CWE-601",
                        owasp="A01:2021 – Broken Access Control",
                        recommendation="Validar URLs contra whitelist de dominios permitidos"
                    ))
    
    def check_eval_injection(self):
        """Detecta uso de eval con input del usuario"""
        for line_num, line in enumerate(self.lines, 1):
            if 'eval(' in line:
                context = '\n'.join(self.lines[max(0, line_num-5):line_num+5])
                if 'request' in context:
                    self.add_vulnerability(Vulnerability(
                        id=f"SEC-012-{line_num}",
                        title="Code Injection (eval)",
                        severity=Severity.CRITICAL.value,
                        description="Uso de eval() con input del usuario, permite ejecución arbitraria de código",
                        file=self.target_file,
                        line=line_num,
                        code=line.strip(),
                        cwe="CWE-95",
                        owasp="A03:2021 – Injection",
                        recommendation="Nunca usar eval() con input del usuario. Usar ast.literal_eval() o parsers específicos"
                    ))
    
    def check_unsafe_imports(self):
        """Detecta imports peligrosos"""
        dangerous_imports = {
            'pickle': "puede ejecutar código arbitrario al deserializar",
            'subprocess': "permite ejecución de comandos del sistema",
            'eval': "ejecuta código Python arbitrario",
            'exec': "ejecuta código Python arbitrario"
        }
        
        for line_num, line in enumerate(self.lines, 1):
            if line.strip().startswith('import ') or ' import ' in line:
                for danger, reason in dangerous_imports.items():
                    if danger in line:
                        if self.verbose:
                            print(f"  [INFO] Import potencialmente peligroso: {danger} en línea {line_num}")


class ReportGenerator:
    """Generador de reportes de vulnerabilidades"""
    
    def __init__(self, vulnerabilities: List[Vulnerability], target_file: str):
        self.vulnerabilities = vulnerabilities
        self.target_file = target_file
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def generate_html(self, output_file: str):
        """Genera reporte en formato HTML"""
        
        # Estadísticas
        stats = self._get_statistics()
        
        html = f"""
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte de Seguridad - {Path(self.target_file).name}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
        }}
        .container {{ 
            max-width: 1200px; 
            margin: 0 auto; 
            padding: 20px;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }}
        .header h1 {{ margin-bottom: 10px; }}
        .header p {{ opacity: 0.9; }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .stat-card h3 {{
            font-size: 2em;
            margin-bottom: 5px;
        }}
        .stat-card p {{ color: #666; }}
        
        .critical {{ border-left: 4px solid #e74c3c; }}
        .high {{ border-left: 4px solid #e67e22; }}
        .medium {{ border-left: 4px solid #f39c12; }}
        .low {{ border-left: 4px solid #3498db; }}
        
        .vulnerability {{
            background: white;
            padding: 25px;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        .vuln-title {{
            font-size: 1.3em;
            font-weight: bold;
        }}
        .severity-badge {{
            padding: 5px 15px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            font-size: 0.85em;
        }}
        .severity-CRITICAL {{ background: #e74c3c; }}
        .severity-HIGH {{ background: #e67e22; }}
        .severity-MEDIUM {{ background: #f39c12; }}
        .severity-LOW {{ background: #3498db; }}
        
        .vuln-meta {{
            display: flex;
            gap: 20px;
            margin-bottom: 15px;
            color: #666;
            font-size: 0.9em;
        }}
        .vuln-meta span {{
            background: #f0f0f0;
            padding: 3px 10px;
            border-radius: 4px;
        }}
        
        .code-block {{
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            margin: 15px 0;
            font-family: 'Courier New', monospace;
        }}
        
        .recommendation {{
            background: #e8f5e9;
            border-left: 4px solid #4caf50;
            padding: 15px;
            margin-top: 15px;
            border-radius: 4px;
        }}
        .recommendation strong {{ color: #2e7d32; }}
        
        .footer {{
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }}
        
        .summary {{
            background: white;
            padding: 25px;
            border-radius: 8px;
            margin-bottom: 30px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        .summary h2 {{
            margin-bottom: 15px;
            color: #667eea;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Reporte de Análisis de Seguridad</h1>
            <p>Archivo: {self.target_file}</p>
            <p>Fecha: {self.timestamp}</p>
        </div>
        
        <div class="stats">
            <div class="stat-card critical">
                <h3>{stats['CRITICAL']}</h3>
                <p>Críticas</p>
            </div>
            <div class="stat-card high">
                <h3>{stats['HIGH']}</h3>
                <p>Altas</p>
            </div>
            <div class="stat-card medium">
                <h3>{stats['MEDIUM']}</h3>
                <p>Medias</p>
            </div>
            <div class="stat-card low">
                <h3>{stats['LOW']}</h3>
                <p>Bajas</p>
            </div>
        </div>
        
        <div class="summary">
            <h2>📊 Resumen Ejecutivo</h2>
            <p>Se encontraron <strong>{len(self.vulnerabilities)} vulnerabilidades</strong> en el archivo analizado.</p>
            <p>Se recomienda priorizar la corrección de vulnerabilidades CRÍTICAS y ALTAS.</p>
        </div>
        
        <h2 style="margin-bottom: 20px;">🔍 Vulnerabilidades Detectadas</h2>
"""
        
        # Ordenar por severidad
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_vulns = sorted(self.vulnerabilities, key=lambda x: severity_order.get(x.severity, 4))
        
        for vuln in sorted_vulns:
            html += f"""
        <div class="vulnerability {vuln.severity.lower()}">
            <div class="vuln-header">
                <div class="vuln-title">{vuln.title}</div>
                <span class="severity-badge severity-{vuln.severity}">{vuln.severity}</span>
            </div>
            
            <div class="vuln-meta">
                <span>📄 Línea {vuln.line}</span>
                <span>🔖 {vuln.cwe}</span>
                <span>🛡️ {vuln.owasp}</span>
            </div>
            
            <p><strong>Descripción:</strong> {vuln.description}</p>
            
            <div class="code-block">
                <div style="color: #75715e;">// Línea {vuln.line}</div>
                {vuln.code}
            </div>
            
            <div class="recommendation">
                <strong>✅ Recomendación:</strong> {vuln.recommendation}
            </div>
        </div>
"""
        
        html += """
        <div class="footer">
            <p>Generado por Analizador de Seguridad Python</p>
            <p>Escenario 4 - Análisis sin ZAP</p>
        </div>
    </div>
</body>
</html>
"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"\n✓ Reporte HTML generado: {output_file}")
    
    def generate_json(self, output_file: str):
        """Genera reporte en formato JSON"""
        report = {
            'metadata': {
                'target_file': self.target_file,
                'timestamp': self.timestamp,
                'total_vulnerabilities': len(self.vulnerabilities),
                'statistics': self._get_statistics()
            },
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities]
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"✓ Reporte JSON generado: {output_file}")
    
    def _get_statistics(self) -> Dict[str, int]:
        """Calcula estadísticas de vulnerabilidades"""
        stats = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for vuln in self.vulnerabilities:
            stats[vuln.severity] += 1
        return stats
    
    def print_console_summary(self):
        """Imprime resumen en consola"""
        stats = self._get_statistics()
        
        print("\n" + "="*70)
        print("📊 RESUMEN DEL ANÁLISIS")
        print("="*70)
        print(f"Archivo: {self.target_file}")
        print(f"Fecha: {self.timestamp}")
        print(f"\nVulnerabilidades encontradas: {len(self.vulnerabilities)}")
        print(f"  🔴 CRÍTICAS: {stats['CRITICAL']}")
        print(f"  🟠 ALTAS: {stats['HIGH']}")
        print(f"  🟡 MEDIAS: {stats['MEDIUM']}")
        print(f"  🔵 BAJAS: {stats['LOW']}")
        print("="*70 + "\n")


class ComparativeAnalyzer:
    """Analizador comparativo entre versión vulnerable y corregida"""
    
    def __init__(self, original_file: str, fixed_file: str):
        self.original_file = original_file
        self.fixed_file = fixed_file
    
    def compare(self) -> Dict:
        """Compara las vulnerabilidades entre ambos archivos"""
        print("\n🔄 Realizando análisis comparativo...\n")
        
        # Analizar ambos archivos
        analyzer_original = SecurityAnalyzer(self.original_file, verbose=False)
        vulns_original = analyzer_original.analyze()
        
        analyzer_fixed = SecurityAnalyzer(self.fixed_file, verbose=False)
        vulns_fixed = analyzer_fixed.analyze()
        
        # Crear grupos por tipo de vulnerabilidad
        original_types = {}
        for vuln in vulns_original:
            if vuln.title not in original_types:
                original_types[vuln.title] = []
            original_types[vuln.title].append(vuln)
        
        fixed_types = {}
        for vuln in vulns_fixed:
            if vuln.title not in fixed_types:
                fixed_types[vuln.title] = []
            fixed_types[vuln.title].append(vuln)
        
        # Identificar correcciones
        corrections = []
        for vuln_type in original_types:
            count_original = len(original_types[vuln_type])
            count_fixed = len(fixed_types.get(vuln_type, []))
            
            if count_fixed < count_original:
                corrections.append({
                    'type': vuln_type,
                    'original_count': count_original,
                    'fixed_count': count_fixed,
                    'status': 'CORREGIDO' if count_fixed == 0 else 'MEJORADO'
                })
        
        return {
            'original_vulns': len(vulns_original),
            'fixed_vulns': len(vulns_fixed),
            'corrections': corrections,
            'reduction_percentage': round((1 - len(vulns_fixed) / len(vulns_original)) * 100, 2) if vulns_original else 100
        }
    
    def generate_comparative_report(self, output_file: str):
        """Genera reporte comparativo HTML"""
        comparison = self.compare()
        
        html = f"""
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Reporte Comparativo de Seguridad</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            padding: 20px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{
            background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .comparison {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }}
        .card {{
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .card h2 {{ font-size: 3em; margin-bottom: 10px; }}
        .original {{ border-top: 4px solid #e74c3c; }}
        .fixed {{ border-top: 4px solid #27ae60; }}
        .improvement {{
            background: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 30px;
        }}
        .improvement h2 {{
            color: #27ae60;
            font-size: 4em;
            text-align: center;
            margin-bottom: 20px;
        }}
        .corrections {{
            background: white;
            padding: 25px;
            border-radius: 8px;
        }}
        .correction-item {{
            padding: 15px;
            margin: 10px 0;
            border-left: 4px solid #27ae60;
            background: #f0f9f4;
        }}
        .correction-item h3 {{ color: #27ae60; }}
        .status-badge {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            background: #27ae60;
            color: white;
            font-size: 0.85em;
            margin-left: 10px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 Análisis Comparativo de Seguridad</h1>
            <p>Comparación entre código vulnerable y corregido</p>
            <p>Fecha: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
        
        <div class="comparison">
            <div class="card original">
                <h2>{comparison['original_vulns']}</h2>
                <p>Vulnerabilidades Originales</p>
                <p style="color: #666; margin-top: 10px;">{self.original_file}</p>
            </div>
            <div class="card fixed">
                <h2>{comparison['fixed_vulns']}</h2>
                <p>Vulnerabilidades Restantes</p>
                <p style="color: #666; margin-top: 10px;">{self.fixed_file}</p>
            </div>
        </div>
        
        <div class="improvement">
            <h2>✅ {comparison['reduction_percentage']}%</h2>
            <p style="text-align: center; font-size: 1.2em; color: #666;">de reducción en vulnerabilidades</p>
        </div>
        
        <div class="corrections">
            <h2 style="margin-bottom: 20px;">🔧 Correcciones Aplicadas</h2>
"""
        
        for correction in comparison['corrections']:
            html += f"""
            <div class="correction-item">
                <h3>{correction['type']} <span class="status-badge">{correction['status']}</span></h3>
                <p>Original: {correction['original_count']} instancias → Corregido: {correction['fixed_count']} instancias</p>
            </div>
"""
        
        html += """
        </div>
    </div>
</body>
</html>
"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"\n✓ Reporte comparativo generado: {output_file}")
        print(f"\n✅ Reducción de vulnerabilidades: {comparison['reduction_percentage']}%")
        print(f"   Original: {comparison['original_vulns']} → Corregido: {comparison['fixed_vulns']}")


def main():
    parser = argparse.ArgumentParser(
        description='Analizador de Seguridad para código Python',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  # Análisis simple
  python analizador_seguridad.py --target app_vulnerable.py
  
  # Análisis con reporte HTML
  python analizador_seguridad.py --target app_vulnerable.py --output reporte.html
  
  # Análisis comparativo
  python analizador_seguridad.py --compare-mode --original app_vulnerable.py --fixed app_corregida.py
  
  # Análisis con formato JSON
  python analizador_seguridad.py --target app.py --output reporte.json --format json
        """
    )
    
    parser.add_argument('--target', help='Archivo Python a analizar')
    parser.add_argument('--output', help='Archivo de salida para el reporte')
    parser.add_argument('--format', choices=['html', 'json'], default='html', help='Formato del reporte')
    parser.add_argument('--compare-mode', action='store_true', help='Modo comparación entre dos archivos')
    parser.add_argument('--original', help='Archivo original (modo comparación)')
    parser.add_argument('--fixed', help='Archivo corregido (modo comparación)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Salida detallada')
    
    args = parser.parse_args()
    
    # Modo comparativo
    if args.compare_mode:
        if not args.original or not args.fixed:
            print("❌ Error: En modo comparación se requiere --original y --fixed")
            return
        
        comparator = ComparativeAnalyzer(args.original, args.fixed)
        output_file = args.output or 'reportes/comparativa.html'
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        comparator.generate_comparative_report(output_file)
        return
    
    # Modo análisis simple
    if not args.target:
        print("❌ Error: Se requiere --target para especificar el archivo a analizar")
        print("Usa --help para ver opciones disponibles")
        return
    
    if not os.path.exists(args.target):
        print(f"❌ Error: El archivo {args.target} no existe")
        return
    
    # Ejecutar análisis
    analyzer = SecurityAnalyzer(args.target, verbose=args.verbose)
    vulnerabilities = analyzer.analyze()
    
    # Generar reporte
    reporter = ReportGenerator(vulnerabilities, args.target)
    reporter.print_console_summary()
    
    if args.output:
        os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else '.', exist_ok=True)
        
        if args.format == 'json':
            reporter.generate_json(args.output)
        else:
            reporter.generate_html(args.output)
    else:
        # Generar reporte por defecto
        default_output = f"reportes/reporte_{Path(args.target).stem}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        os.makedirs('reportes', exist_ok=True)
        reporter.generate_html(default_output)


if __name__ == '__main__':
    main()
