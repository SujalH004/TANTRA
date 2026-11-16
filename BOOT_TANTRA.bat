@echo off
color 0a
title T.A.N.T.R.A. Tactical Node - FIELD COMMAND
echo =======================================================
echo [*] T.A.N.T.R.A. ZERO-FOOTPRINT TACTICAL NODE
echo =======================================================

:: 1. VERIFY CRITICAL OFFLINE ASSETS
echo [!] VERIFYING OFFLINE UI ASSETS...
if not exist "static\socket.io.min.js" (
    color 0c
    echo [CRITICAL WARNING] socket.io.min.js is MISSING from the \static\ folder!
    echo [CRITICAL WARNING] The WebSockets will fail and the UI will not load.
    echo Please download Socket.IO v4.x into the static folder.
    timeout /t 5 >nul
    color 0a
)

if not exist "static\d3.v7.min.js" (
    color 0c
    echo [WARNING] d3.v7.min.js is MISSING from the \static\ folder!
    echo [WARNING] The mesh topology radar will not render correctly.
    timeout /t 3 >nul
    color 0a
)

:: 2. SYNC PYTHON DEPENDENCIES
echo [!] SYNCING PYTHON DEPENDENCIES (requirements.txt)...
pip install -r requirements.txt >nul 2>&1

:: 3. BOOT SECURE LOCAL SERVER
echo [!] BOOTING SECURE SERVER ENVIRONMENT...
echo =======================================================
python app.py

:: Keep terminal open if the server crashes
pause