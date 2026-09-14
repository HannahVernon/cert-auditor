@echo off
REM Builds CertAuditor in Release configuration.
REM Run this from a normal (non-administrator) command prompt - building
REM does not require administrator privileges. Only running "capture" does.

setlocal
cd /d "%~dp0"

echo.
echo === Restoring and building CertAuditor (Release) ===
echo.

dotnet build CertAuditor.sln --configuration Release
if errorlevel 1 (
    echo.
    echo *** BUILD FAILED - see errors above. ***
    echo.
    echo If the error mentions a missing "net48" reference assembly or
    echo targeting pack, install the .NET Framework 4.8 Developer Pack:
    echo https://dotnet.microsoft.com/en-us/download/dotnet-framework/net48
    echo.
    exit /b 1
)

echo.
echo === Build succeeded ===
echo Executable: %~dp0CertAuditor\bin\Release\net48\CertAuditor.exe
echo.
echo Next step: open an elevated (Run as administrator) command prompt and run:
echo   "%~dp0CertAuditor\bin\Release\net48\CertAuditor.exe" --help
echo.

endlocal
