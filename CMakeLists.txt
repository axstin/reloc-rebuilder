cmake_minimum_required(VERSION 3.0.0)
project(reloc-rebuilder VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

file(GLOB_RECURSE SOURCES src/*.cpp)

add_executable(reloc-rebuilder ${SOURCES})
