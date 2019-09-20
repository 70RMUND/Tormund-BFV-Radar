powershell -Command "Start-Process 'python' -Verb runAs -ArgumentList 'Radar.py 800 600'"
@if NOT ["%errorlevel%"]==["0"] pause