@echo off
rem ARTEX supervisor script (Windows). ASCII-only on purpose:
rem cmd.exe can mis-parse batch files that contain multibyte characters when
rem the active code page is 65001 (UTF-8), so keep this file plain ASCII.
rem
rem Usage:
rem   start.bat                 run in foreground (Ctrl-C to stop)
rem   start.bat -addr :9000     extra args are passed through to artex.exe
rem
rem What it does: run artex.exe, then decide by exit code whether to relaunch.
rem   0      user stop       -> exit loop
rem   75     restart request -> relaunch at once (self-update / rollback)
rem   other  crash           -> relaunch with backoff (1,2,4... up to 60s)
rem
rem Database gate: before each launch it checks port 5432. If the port already
rem listens, the check is skipped entirely (no double-start, no conflict).
rem Otherwise it starts the Windows service postgresql-x64-16 if stopped and
rem waits up to about 90s for the port; on timeout artex is launched anyway
rem and its own retry loop takes over.
rem
rem Download / SHA256 check / binary swap are done by artex itself (selfupdate).

chcp 65001 >nul 2>&1

setlocal enabledelayedexpansion
cd /d "%~dp0"

set "BIN=artex.exe"
if not exist "%BIN%" (
	echo [artex] executable not found: %BIN% 1>&2
	exit /b 1
)

rem --- single-instance guard --------------------------------------------------
rem If the default port 8787 already has a listener, an instance is probably
rem running already (for example the scheduled task "ARTEX"). Exit with a hint
rem instead of relaunch-looping with bind errors. Skipped when the caller
rem passes a custom -addr / --addr.
set "CUSTOM_ADDR="
if not "%~1"=="" (
	for %%A in (%*) do (
		set "tok=%%~A"
		if /i "!tok:~0,5!"=="-addr" set "CUSTOM_ADDR=1"
		if /i "!tok:~0,6!"=="--addr" set "CUSTOM_ADDR=1"
	)
)
if not defined CUSTOM_ADDR (
	netstat -ano -p tcp | findstr /i "LISTENING" | findstr /i /c:":8787 " >nul 2>&1
	if not errorlevel 1 (
		echo [artex] Port 8787 already has a listener - an instance is probably running
		echo [artex] already, e.g. the scheduled task ARTEX. Not relaunching, to avoid
		echo [artex] a flood of bind errors. Backend logs: web UI, System Config
		echo [artex] page "Backend Logs". To run here anyway, stop the existing
		echo [artex] instance first, or pass a custom -addr.
		rem keep the window readable on double-click; bounded so non-interactive runs never hang
		timeout /t 10 >nul 2>&1
		exit /b 1
	)
)
rem ----------------------------------------------------------------------------

set "RESTART_CODE=75"
set "MAX_DELAY=60"
set /a delay=1

:loop
rem --- database gate ----------------------------------------------------------
rem Fast path: port 5432 already listening means the DB is up - skip all of
rem this. Slow path: start the service if stopped, then wait for the port.
rem Port 5432 must match the database host/port in config.json.
netstat -ano -p tcp | findstr /i "LISTENING" | findstr /i /c:":5432 " >nul 2>&1
if not errorlevel 1 goto :db_ok

echo [artex] PostgreSQL is not reachable on port 5432 yet.
sc query postgresql-x64-16 2>nul | findstr /i "RUNNING" >nul 2>&1
if not errorlevel 1 goto :db_wait
sc query postgresql-x64-16 >nul 2>&1
if errorlevel 1 goto :db_missing
echo [artex] Starting Windows service postgresql-x64-16...
net start postgresql-x64-16 >nul 2>&1
if errorlevel 1 echo [artex] Could not start the service - admin rights required? Waiting for the port anyway...

:db_wait
set /a db_tries=0
echo [artex] Waiting for PostgreSQL to accept connections on port 5432...
:db_spin
netstat -ano -p tcp | findstr /i "LISTENING" | findstr /i /c:":5432 " >nul 2>&1
if not errorlevel 1 goto :db_up
set /a db_tries+=1
if !db_tries! geq 90 goto :db_late
ping -n 2 127.0.0.1 >nul 2>&1
goto :db_spin

:db_late
echo [artex] Warning: PostgreSQL still down after about 90s - launching artex anyway, it will keep retrying.
goto :db_ok

:db_up
echo [artex] PostgreSQL is up - launching artex.
goto :db_ok

:db_missing
echo [artex] Service postgresql-x64-16 not found - assuming an external database, launching artex.
goto :db_ok

:db_ok
"%BIN%" %*
set "code=!ERRORLEVEL!"

if "!code!"=="0" (
	echo [artex] exited normally
	exit /b 0
)

if "!code!"=="%RESTART_CODE%" (
	rem update/rollback staged: relaunch now to finish the swap
	echo [artex] restart requested, applying new version...
	set /a delay=1
	goto loop
)

echo [artex] crashed ^(code=!code!^), relaunching in !delay!s 1>&2
rem "timeout" fails under redirected consoles; ping is the fallback
set /a pings=!delay!+1
ping -n !pings! 127.0.0.1 >nul 2>&1
set /a delay=!delay!*2
if !delay! gtr %MAX_DELAY% set /a delay=%MAX_DELAY%
goto loop
