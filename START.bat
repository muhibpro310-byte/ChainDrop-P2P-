@echo off
echo ========================================
echo   ChainDrop - Secure P2P File Transfer
echo ========================================
echo.
echo Installing required packages...
pip install flask flask-socketio cryptography
echo.
echo Starting server...
echo Your browser will open automatically.
echo For the multi-user demo, open more tabs at http://localhost:5000
echo.
python app.py
pause
