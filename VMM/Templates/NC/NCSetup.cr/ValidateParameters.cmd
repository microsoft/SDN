@echo off
chcp 437

@PowerShell -NonInteractive -NoProfile -ExecutionPolicy Unrestricted -Command "& {.\ValidateParameters.ps1 %*; exit $LastExitCode }"
exit /B %errorlevel%
