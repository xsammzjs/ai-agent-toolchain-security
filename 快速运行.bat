@echo off
chcp 65001 >nul
if defined SB_MAIN goto :__main__
set "SB_MAIN=1"
cmd /c call "%~f0" %*
exit /b
:__main__
set "SB_MAIN="
setlocal enabledelayedexpansion
title AI 技能与依赖漏洞检测平台 - 一键启动
cd /d "%~dp0"

REM ==========================================================
REM  快速运行.bat —— Windows 一键启动入口
REM
REM  本文件只做两件事：
REM    1. 找到一个能用的 Python 解释器
REM    2. 把启动工作交给 start.py（唯一的启动逻辑，端口避让、
REM       浏览器打开、依赖检测都在那里，避免两套逻辑各自漂移）
REM
REM  start.py 需要的第三方包（实际检测逻辑在 start.py 里）：
REM    streamlit / pandas / requests / nvdlib / packaging
REM    docx / reportlab / dotenv / rarfile
REM ==========================================================

REM ---------- 找一个能用的 Python ----------
set "PYEXE="
if exist ".venv\Scripts\python.exe" (
  set "PYEXE=%CD%\.venv\Scripts\python.exe"
  goto :have_python
)

echo [1/5] 未找到项目虚拟环境，正在查找系统 Python ...
set "BOOTPY="
where py >nul 2>nul
if not errorlevel 1 (
  py -3 --version >nul 2>nul
  if not errorlevel 1 set "BOOTPY=py -3"
)
if not defined BOOTPY (
  where python >nul 2>nul
  if not errorlevel 1 (
    python --version >nul 2>nul
    if not errorlevel 1 set "BOOTPY=python"
  )
)
if not defined BOOTPY (
  echo.
  echo [错误] 没有检测到 Python。
  echo        请先安装 Python 3.11 或 3.13：https://www.python.org/downloads/
  echo        安装时务必勾选 "Add Python to PATH"，装完后重新双击本脚本。
  echo.
  pause
  exit /b 1
)
set "PYEXE=%BOOTPY%"

:have_python
echo 正在交给 start.py 启动，请稍候 ...
echo   停止服务： 按 Ctrl+C，或直接关闭本窗口
echo.

REM ---------- 启动（--ask-port：端口被占用时让你选怎么处理） ----------
setlocal EnableDelayedExpansion
"%PYEXE%" "%~dp0start.py" --ask-port %*
set "RC=!ERRORLEVEL!"
endlocal & set "RC=%RC%"

echo.
if "%RC%"=="2" (
  echo 已取消启动（你选择了不启动）。
  echo.
  pause
  exit /b 0
)
if not "%RC%"=="0" (
  echo [启动失败] 请把上面红色的错误信息截图发给开发者。
  echo.
  pause
  exit /b %RC%
)
echo 服务已停止。关闭本窗口即彻底结束服务。
echo.
pause
exit /b 0
