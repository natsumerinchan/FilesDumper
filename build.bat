@chcp 65001
@echo off

if exist ".\build\" rmdir /s /q ".\build"
cmake -S . -B build -G "Visual Studio 17 2022" -A win32 && cmake --build build --config Release
pause