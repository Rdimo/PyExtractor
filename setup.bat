py -m pip install -r requirements.txt
cls
echo py main.py >> run.bat
start run.bat
start /b "" cmd /c del "%~f0"&exit /b