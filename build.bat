@echo off
setlocal enabledelayedexpansion

echo === Rust Dictionary-Based Shellcode Execution Utility Build Script ===

:: Check if Rust is installed
where rustc >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo Error: Rust is not installed! Please install Rust first.
    echo Visit https://rustup.rs for installation instructions.
    exit /b 1
)

:: Display versions
echo Using Rust version:
rustc --version

echo Using Cargo version:
cargo --version

echo Checking dependencies...
cargo check

:: Build options
echo Select build type:
echo 1) Debug build (faster compilation, better for development)
echo 2) Release build (optimized, smaller binary)
set /p BUILD_TYPE=Select option [2]: 

if not defined BUILD_TYPE set BUILD_TYPE=2

if "%BUILD_TYPE%"=="1" (
    echo Building debug version...
    cargo build
    set BINARY_PATH=target\debug\rust-run.exe
) else (
    echo Building release version...
    cargo build --release
    set BINARY_PATH=target\release\rust-run.exe
)

:: Check if build was successful
if exist "!BINARY_PATH!" (
    echo Build successful!
    
    :: Binary info
    echo Binary information:
    dir "!BINARY_PATH!"
    
    :: Ask to run the program
    set /p RUN_NOW=Run the program now? (y/n) [n]: 
    
    if not defined RUN_NOW set RUN_NOW=n
    
    if /i "!RUN_NOW!"=="y" (
        echo Running the program...
        set /p DEBUG_LOG=Enable debug logging? (y/n) [n]: 
        
        if not defined DEBUG_LOG set DEBUG_LOG=n
        
        if /i "!DEBUG_LOG!"=="y" (
            set RUST_LOG=debug
            "!BINARY_PATH!"
        ) else (
            "!BINARY_PATH!"
        )
    ) else (
        echo To run the program manually:
        echo !BINARY_PATH!
        echo For debug logging: set RUST_LOG=debug ^&^& !BINARY_PATH!
    )
) else (
    echo Build failed! Binary not found at !BINARY_PATH!
    exit /b 1
)

endlocal
