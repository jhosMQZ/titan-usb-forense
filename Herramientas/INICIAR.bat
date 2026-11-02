@echo off
rem Relanza el menu desde el punto de confianza (dentro de WinPE).
rem No ejecuta nada de esta particion directamente: Iniciar.ps1 verifica
rem la integridad antes de usar los scripts.
if not exist X:\Ancla\Iniciar.ps1 (
  echo Este USB solo se usa arrancando desde el. No ejecute nada aqui en Windows.
  pause
  exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass -File X:\Ancla\Iniciar.ps1
