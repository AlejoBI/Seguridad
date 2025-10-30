@echo off
echo ========================================
echo Instalacion - Escenario 4 Python
echo ========================================
echo.

REM Verificar Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python no esta instalado o no esta en el PATH
    echo Descarga Python desde: https://www.python.org/downloads/
    pause
    exit /b 1
)

echo [1/4] Python detectado correctamente
echo.

REM Crear entorno virtual
echo [2/4] Creando entorno virtual...
if exist venv (
    echo Entorno virtual ya existe, eliminando...
    rmdir /s /q venv
)
python -m venv venv
echo.

REM Activar entorno virtual
echo [3/4] Activando entorno virtual...
call venv\Scripts\activate.bat
echo.

REM Instalar dependencias
echo [4/4] Instalando dependencias...
pip install --upgrade pip
pip install -r requirements.txt
echo.

echo ========================================
echo Instalacion completada exitosamente!
echo ========================================
echo.
echo Para activar el entorno virtual en el futuro:
echo   venv\Scripts\activate
echo.
echo Para ejecutar el analisis:
echo   python analizador_seguridad.py --target app_vulnerable.py
echo.
echo Para ejecutar la demo completa:
echo   python demo.py
echo.
pause
