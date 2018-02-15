@echo off

:: Set current dir of this script
cd /d %~dp0

if "%~1" == "" (
    echo Usage: ^<htpac'd exe file to unpac^>
    goto DONE
)
:: Load htpac kernel module
copy HtsysmNT.sys C:\HtsysmNT.sys > null
sc create htpac type= kernel binPath= C:\HtsysmNT.sys > null

if %ERRORLEVEL% neq 0 (
    echo Loading kernel module failed
    goto DONE
)

sc start htpac > null

if %ERRORLEVEL% neq 0 (
    echo Starting kernel module failed
    goto DONE
)

:: Run program that creates the .bak file and changes the dll name in the exe
pre-dump.exe %1

::echo Unpac'ing %1 ...
%1

:: Stop and unload kernel module
sc stop htpac > null
sc delete htpac > null
del C:\HtsysmNT.sys > null

:: Revert altered exec and backup
for %%i IN ("%1") do (
    move %%~ni.bak %1
)

echo Done

:DONE
