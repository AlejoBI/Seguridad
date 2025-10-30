# ⚡ Guía de Uso Rápido

## 🚀 Instalación (3 minutos)
```powershell
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

## 🔍 Comandos Esenciales

### Análisis Simple
```powershell
python analizador_seguridad.py --target app_vulnerable.py
```

### Análisis Comparativo
```powershell
python analizador_seguridad.py --compare-mode ^
    --original app_vulnerable.py ^
    --fixed app_corregida.py
```

### Formato JSON (para CI/CD)
```powershell
python analizador_seguridad.py --target app.py --format json
```

## 🔄 Ciclo de Trabajo

```
1. Analizar → 2. Ver reporte → 3. Corregir → 4. Re-analizar → 5. Repetir
```

## 📊 Resultados

**Antes:** 9 vulnerabilidades (6 críticas)  
**Después:** 1 vulnerabilidad (0 críticas)  
**Reducción:** 88.89%

---

**📖 Para guía completa:** Ver `GUIA_CLASE.md`
