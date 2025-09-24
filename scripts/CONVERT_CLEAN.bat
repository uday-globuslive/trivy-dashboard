@echo off
title SBOM to Trivy Report Converter - Clean Version

echo ================================
echo SBOM to Trivy Report Converter
echo Clean Version with .env Configuration
echo ================================
echo.

cd /d "%~dp0"

:menu
echo Select conversion mode:
echo.
echo [1] Test Environment (Check configuration and connectivity)
echo [2] Dry Run (Show what would be converted without changes)  
echo [3] Convert SBOM Files (Live conversion - limit 10 files)
echo [4] Convert All SBOM Files (Process all available files)
echo [5] Force Convert (Overwrite existing Trivy reports)
echo [6] Exit
echo.
set /p choice="Enter your choice (1-6): "

if "%choice%"=="1" goto test_env
if "%choice%"=="2" goto dry_run  
if "%choice%"=="3" goto convert_limited
if "%choice%"=="4" goto convert_all
if "%choice%"=="5" goto force_convert
if "%choice%"=="6" goto exit
echo Invalid choice, please try again.
goto menu

:test_env
echo Running environment test...
powershell -ExecutionPolicy Bypass -File "test-env.ps1"
goto menu

:dry_run
echo Running dry run conversion test...
powershell -ExecutionPolicy Bypass -Command ".\convert-sbom-clean.ps1 -DryRun"
pause
goto menu

:convert_limited
echo Converting SBOM files (limited to 10)...
echo This will perform actual conversions!
set /p confirm="Are you sure? (y/N): "
if /i not "%confirm%"=="y" goto menu
powershell -ExecutionPolicy Bypass -Command ".\convert-sbom-clean.ps1 -MaxFiles 10"
pause
goto menu

:convert_all
echo Converting ALL SBOM files...
echo WARNING: This will process all available SBOM files!
set /p confirm="Are you sure? (y/N): "
if /i not "%confirm%"=="y" goto menu
powershell -ExecutionPolicy Bypass -Command ".\convert-sbom-clean.ps1"
pause
goto menu

:force_convert
echo Force converting SBOM files (overwrite existing reports)...
echo WARNING: This will overwrite existing Trivy reports!
set /p confirm="Are you sure? (y/N): "
if /i not "%confirm%"=="y" goto menu
powershell -ExecutionPolicy Bypass -Command ".\convert-sbom-clean.ps1 -Force -MaxFiles 10"
pause
goto menu

:exit
echo Goodbye!
pause > nul