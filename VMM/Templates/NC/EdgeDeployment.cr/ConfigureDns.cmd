@echo off
chcp 437

@PowerShell -NonInteractive -NoProfile -ExecutionPolicy Unrestricted -Command "& {./ConfigureDns.ps1 %1; exit $LastExitCode }"
exit /B %errorlevel%
