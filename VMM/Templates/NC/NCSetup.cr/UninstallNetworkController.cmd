@echo off
chcp 437

@PowerShell -NonInteractive -NoProfile -ExecutionPolicy Unrestricted -Command "& {.\UninstallNetworkController.ps1 %*; exit $LastExitCode }"
exit /B %errorlevel%
