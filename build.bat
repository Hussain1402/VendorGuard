@echo off
REM Build VendorGuard.exe on Windows. Requires Go 1.22 or newer (https://go.dev/dl/).
echo Running tests...
go test ./...
if errorlevel 1 exit /b 1
echo Building bin\VendorGuard.exe ...
if not exist bin mkdir bin
go build -trimpath -ldflags "-s -w" -o bin\VendorGuard.exe .
if errorlevel 1 exit /b 1
echo Done. Run bin\VendorGuard.exe
