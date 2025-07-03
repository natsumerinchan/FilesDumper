cmake_minimum_required(VERSION 3.10)
project(FilesDumper LANGUAGES CXX)

if(MSVC)
    add_compile_options(/utf-8)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 添加DLL目标
add_library(FilesDumper SHARED src/dllmain.cpp)

# 包含Detours头文件
target_include_directories(FilesDumper PRIVATE detours)

# 链接Detours库
target_link_libraries(FilesDumper PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/detours/detours.lib)

# 设置输出目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
