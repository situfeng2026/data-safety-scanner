@echo off
chcp 65001 >nul
title 数据安全检查工具 - 一键构建

echo ==================================================
echo   数据安全检查工具 - 自动构建
echo ==================================================
echo.
echo 此脚本将自动安装 Python 依赖并打包为 .exe
echo.

:: 检查 Python
where python >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [步骤 1/3] 未检测到 Python，正在下载 Python...
    curl -o "%TEMP%\python-installer.exe" https://www.python.org/ftp/python/3.12.4/python-3.12.4-amd64.exe
    echo 请按提示安装 Python（务必勾选 "Add Python to PATH"）
    start /wait "%TEMP%\python-installer.exe"
    echo 安装完成后请重新运行此脚本。
    pause
    exit /b
)

echo [步骤 1/3] Python 已安装 ✓
python --version

echo.
echo [步骤 2/3] 正在安装 PyInstaller...
pip install pyinstaller -q
echo PyInstaller 安装完成 ✓

echo.
echo [步骤 3/3] 正在打包为 .exe（可能需要1-2分钟）...
pyinstaller --onefile --windowed --name "DataSafetyScanner" --add-data "README.md;." --distpath "." --workpath "%TEMP%\pyibuild" --specpath "%TEMP%\pyispec" "%~dp0DataSafetyScanner.py"

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ==================================================
    echo   ✅ 构建成功！
    echo ==================================================
    echo.
    echo 生成文件: %~dp0DataSafetyScanner.exe
    echo 文件大小: 
    dir "%~dp0DataSafetyScanner.exe"
    echo.
    echo 双击 DataSafetyScanner.exe 即可运行
    echo.
) else (
    echo.
    echo ❌ 构建失败，请检查错误信息
    echo.
)

pause
