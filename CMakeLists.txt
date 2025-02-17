cmake_minimum_required(VERSION 3.5.0)
project(NPS VERSION 0.1.0 LANGUAGES C)
set(C_STANDARD 23)

file(GLOB_RECURSE SOURCES "src/*.c" "src./*.h")

add_executable(NPS ${SOURCES})

