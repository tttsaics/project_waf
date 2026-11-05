cmake_minimum_required(VERSION 3.20)
project(waf_firewall CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)

if (WIN32)
    add_definitions(-D_WIN32_WINNT=0x0A00)
endif()

file(GLOB SOURCES 
    "src/*.cpp"
)

add_executable(waf ${SOURCES})

if (WIN32)
    target_link_libraries(waf PRIVATE ws2_32)
endif()
