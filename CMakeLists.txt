cmake_minimum_required(VERSION 3.13.4)
project(xmps)

set(COMPILER_FLAGS " \
-Wno-sign-compare -ggdb3 -O2 -pipe -D_FORTIFY_SOURCE=2 \
-fstack-protector-strong -grecord-gcc-switches -flto -fstack-clash-protection  \
-Wall -Wextra -Werror=format-security -Werror=switch-unreachable \
-Werror=vla -Werror=implicit-fallthrough")

set(CMAKE_C_FLAGS "-std=gnu11 -Wstrict-prototypes -Wmissing-prototypes -Werror=implicit-function-declaration ${COMPILER_FLAGS}")
set(CMAKE_CXX_FLAGS "-std=gnu++17 -fexceptions ${COMPILER_FLAGS}")

# prevent cmake from setting -std=... flags on its own
set(CMAKE_CXX_STANDARD_DEFAULT "")

set(SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

add_executable(xmps-server
        ${SOURCE_DIR}/server.c
        )

target_link_libraries(xmps-server uring)
target_include_directories(xmps-server PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR} ${SOURCE_DIR}/include ${URING_INCLUDE_DIRS})
target_compile_definitions(xmps-server PRIVATE _GNU_SOURCE=1)
set_target_properties(xmps-server PROPERTIES C_STANDARD 11 CXX_STANDARD 17)
