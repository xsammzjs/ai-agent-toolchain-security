@echo off
chcp 65001 >nul
if "%~1"=="__main__" goto :__main__
cmd /c call "%~f0" __main__
exit /b
:__main__
setlocal enabledelayedexpansion
title AI 技能与依赖漏洞检测平台 - 一键启动
cd /d "%~dp0"

set "APP_TITLE=AI 技能与依赖漏洞检测平台"
set "DEFAULT_PORT=8501"
set "PORT=%DEFAULT_PORT%"
set "PYEXE="
set "PORT_BUSY=0"
set "PORT_PID="
set "CANCELLED="

echo ============================================
echo   %APP_TITLE%  一键启动
echo   AI 技能静态规则检测  依赖漏洞四源交叉验证
echo ============================================
echo.

REM ================= [1/5] Python 解释器 =================
call :ensure_python
if errorlevel 1 goto :fail

REM ================= [2/5] 依赖检测 =================
call :ensure_deps
if errorlevel 1 goto :fail

REM ================= [3/5] 配置文件检查 =================
call :ensure_env

REM ================= [4/5] 端口检测 =================
call :pick_port
if errorlevel 1 goto :fail
if defined CANCELLED goto :done

REM ================= [5/5] 启动服务 =================
call :launch
goto :done


REM ==========================================================
REM  失败出口
REM ==========================================================
:fail
echo.
echo [启动失败] 请把上面红色的错误信息截图发给开发者。
echo.
pause
exit /b 1


REM ==========================================================
REM  正常结束出口
REM ==========================================================
:done
if defined CANCELLED (
  echo.
  echo 已取消启动。
  echo.
  pause
  exit /b 0
)
echo.
echo 服务已停止。关闭本窗口即彻底结束服务。
echo.
pause
exit /b 0


REM ==========================================================
REM  [1/5] 准备 Python 解释器
REM  优先复用项目内 .venv；没有才用系统 Python 创建
REM ==========================================================
:ensure_python
if exist ".venv\Scripts\python.exe" (
  set "PYEXE=%CD%\.venv\Scripts\python.exe"
  echo [1/5] 找到项目虚拟环境 .venv，直接复用（不用重复装依赖）
  exit /b 0
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
  exit /b 1
)

echo       使用 %BOOTPY% 创建虚拟环境 .venv ...
setlocal disabledelayedexpansion
%BOOTPY% -m venv .venv
if errorlevel 1 (
  endlocal
  echo.
  echo [错误] 创建虚拟环境失败，请检查 Python 安装是否完整。
  exit /b 1
)
endlocal
set "PYEXE=%CD%\.venv\Scripts\python.exe"
exit /b 0


REM ==========================================================
REM  [2/5] 依赖检测 —— 缺什么装什么，已齐全则完全不重装
REM ==========================================================
:ensure_deps
set "MISSING="
for %%M in (streamlit pandas requests nvdlib packaging docx reportlab dotenv rarfile) do (
  "%PYEXE%" -c "import %%M" >nul 2>nul
  if errorlevel 1 set "MISSING=!MISSING! %%M"
)
if not defined MISSING (
  echo [2/5] 依赖检查通过，组件都已就绪（不会重复安装）
  exit /b 0
)

echo [2/5] 检测到缺失依赖：!MISSING!
echo       正在自动安装，请稍候（首次运行约需 2-5 分钟）...
setlocal disabledelayedexpansion
"%PYEXE%" -m pip install --upgrade pip -q
"%PYEXE%" -m pip install -r requirements.txt
if errorlevel 1 (
  endlocal
  echo.
  echo [错误] 依赖安装失败，通常是网络问题。
  echo        可以换国内镜像源重试：
  echo        "%PYEXE%" -m pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
  exit /b 1
)
endlocal
echo       依赖安装完成。
exit /b 0


REM ==========================================================
REM  [3/5] 配置文件检查（.env 缺失不影响启动，只降级）
REM ==========================================================
:ensure_env
if exist ".env" (
  echo [3/5] 配置文件 .env 已就绪
  exit /b 0
)
echo [3/5] 未找到配置文件 .env，程序依然可以运行，但有以下影响：
echo        1. NVD 漏洞库走匿名接口，每次查询约 6 秒，扫描明显变慢
echo        2. 多源交叉验证的置信度评级降级为单源，结论可信度下降
echo        3. 当前若没有网络，请用界面里的「离线演示模式」查看预置场景
echo        需要配置文件的话，复制 .env.example 为 .env 即可（密钥可留空）
exit /b 0


REM ==========================================================
REM  [4/5] 端口检测与避让
REM ==========================================================
:pick_port
call :is_port_busy %DEFAULT_PORT%
if "!PORT_BUSY!"=="0" (
  set "PORT=%DEFAULT_PORT%"
  echo [4/5] 端口 %DEFAULT_PORT% 可用。
  exit /b 0
)
set /a "PICK_TRIES=0"

:pick_prompt
echo.
echo [警告] 端口 %DEFAULT_PORT% 已被占用（占用进程 PID：!PORT_PID!）。
echo        很可能是之前启动的服务还在运行（那个黑窗口没关）。
echo.
echo        [1] 停掉占用端口的旧进程，继续用 %DEFAULT_PORT%
echo        [2] 换一个端口启动（自动找 8502、8503 ...）
echo        [0] 取消本次启动
echo.
set "CHOICE="
set /p "CHOICE=请输入数字后按回车 [1/2/0]：" 
if "!CHOICE!"=="1" goto :kill_old
if "!CHOICE!"=="2" goto :find_next
if "!CHOICE!"=="0" (
  set "CANCELLED=1"
  exit /b 0
)
set /a "PICK_TRIES+=1"
if !PICK_TRIES! gtr 5 (
  echo.
  echo [错误] 多次输入无效，已取消启动。
  set "CANCELLED=1"
  exit /b 0
)
echo.
echo 输入无效，请重新选择。
goto :pick_prompt


REM ---------- 选项 1：结束占用端口的旧进程 ----------
:kill_old
echo.
echo 正在结束占用端口的旧进程（PID !PORT_PID!）...
setlocal disabledelayedexpansion
taskkill /PID %PORT_PID% /F >nul 2>nul
endlocal
if errorlevel 1 (
  echo [提示] 没能结束该进程，可能需要以管理员身份运行。
  echo        请手动关掉之前的服务窗口，或选择 [2] 换个端口。
  goto :pick_prompt
)
ping -n 2 127.0.0.1 >nul
call :is_port_busy %DEFAULT_PORT%
if "!PORT_BUSY!"=="1" (
  echo [提示] 端口仍被占用，请选择 [2] 换个端口。
  goto :pick_prompt
)
set "PORT=%DEFAULT_PORT%"
echo 端口 %DEFAULT_PORT% 已释放，可以启动。
exit /b 0


REM ---------- 选项 2：自动找一个空闲端口 ----------
:find_next
set /a "P=8502"

:find_next_loop
if !P! gtr 8599 (
  echo.
  echo [错误] 8502 到 8599 都被占用了，请先关掉一些程序后重试。
  exit /b 1
)
call :is_port_busy !P!
if "!PORT_BUSY!"=="0" (
  set "PORT=!P!"
  echo [4/5] 端口 !P! 可用，将用它启动。
  exit /b 0
)
set /a "P+=1"
goto :find_next_loop


REM ==========================================================
REM  端口占用检测（netstat，不依赖管理员权限）
REM  入参 %1 = 端口号；输出 PORT_BUSY=0/1、PORT_PID=占用进程 PID
REM ==========================================================
:is_port_busy
set "PORT_BUSY=0"
set "PORT_PID="
for /f "tokens=5" %%P in ('netstat -ano -p TCP 2^>nul ^| findstr "LISTENING" ^| findstr ":%1 "') do (
  if not defined PORT_PID (
    set "PORT_BUSY=1"
    set "PORT_PID=%%P"
  )
)
exit /b 0


REM ==========================================================
REM  [5/5] 启动服务
REM ==========================================================
:launch
echo.
echo ============================================
echo   正在启动服务，请稍候 ...
echo ============================================
echo.
echo   访问地址： http://localhost:%PORT%
echo   停止服务： 按 Ctrl+C 或直接关闭本窗口
echo.
echo   3 秒后会自动打开浏览器；没弹出来就手动复制上面的地址。
echo.

REM 延时约 3 秒后自动打开浏览器（ping 当定时器用，比 timeout 更稳）
start "" /b cmd /c "ping -n 4 127.0.0.1 >nul & start "" http://localhost:%PORT%"

setlocal disabledelayedexpansion
"%PYEXE%" -m streamlit run main.py --server.port %PORT% --server.address 127.0.0.1 --server.headless true
endlocal
exit /b 0
