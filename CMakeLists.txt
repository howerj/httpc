cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(httpc
    VERSION 4.1.2
    LANGUAGES C)

function(ensure_int VAR)
  string(STRIP "${VAR}" parsed)
  if (NOT parsed MATCHES "^[0-9]+$")
    message(FATAL_ERROR "Expected number, got '${VAR}'")
  endif()
endfunction()


option(HTTPC_USE_SSL "SSL support" OFF)
set(HTTPC_STACK_BUFFER_SIZE 128 CACHE STRING "")
option(HTTPC_TESTS_ON "" ON)
option(HTTPC_GROW "" ON)
option(HTTPC_LOGGING "" ON)
set(HTTPC_CONNECTION_ATTEMPTS 3 CACHE STRING "")
set(HTTPC_REDIRECT_MAX 3 CACHE STRING "")
set(HTTPC_MAX_HEADER 8192 CACHE STRING "")
option(HTTPC_ALLOW_ANY_RESPONSE_STRING "" OFF)

ensure_int(${HTTPC_STACK_BUFFER_SIZE})
ensure_int(${HTTPC_CONNECTION_ATTEMPTS})
ensure_int(${HTTPC_REDIRECT_MAX})
ensure_int(${HTTPC_MAX_HEADER})

if(WIN32)
    set(HTTPC_PLATFORM_SRCS
        win.c)
    add_library(httpc_platform STATIC ${HTTPC_PLATFORM_SRCS})
    target_compile_definitions(httpc_platform PRIVATE USE_SSL=$<BOOL:${HTTPC_USE_SSL}>)
    set_property(TARGET httpc_platform PROPERTY C_STANDARD 99)
    set_property(TARGET httpc_platform PROPERTY C_STANDARD_REQUIRED ON)
    set_property(TARGET httpc_platform PROPERTY C_EXTENSIONS OFF)
endif()

if(UNIX)
    set(HTTPC_PLATFORM_SRCS
        unix.c)
    add_library(httpc_platform STATIC ${HTTPC_PLATFORM_SRCS})
    target_compile_definitions(httpc_platform PRIVATE USE_SSL=$<BOOL:${HTTPC_USE_SSL}>)
    set_property(TARGET httpc_platform PROPERTY C_STANDARD 99)
    set_property(TARGET httpc_platform PROPERTY C_STANDARD_REQUIRED ON)
    set_property(TARGET httpc_platform PROPERTY C_EXTENSIONS ON)
endif()

if(${HTTPC_USE_SSL})
    find_package(OpenSSL REQUIRED)
    target_link_libraries(httpc_platform PRIVATE OpenSSL::SSL)
endif()



set(HTTPC_LIB_SRCS
    httpc.c
    httpc.h
    localely.h)

add_library(httpc_lib STATIC ${HTTPC_LIB_SRCS})
target_link_libraries(httpc_lib PRIVATE httpc_platform)
target_compile_definitions(httpc_lib
    PUBLIC
    HTTPC_VERSION="${PROJECT_VERSION}"
    PRIVATE
    HTTPC_STACK_BUFFER_SIZE=${HTTPC_STACK_BUFFER_SIZE}ul
    HTTPC_TESTS_ON=$<BOOL:${HTTPC_TESTS_ON}>
    HTTPC_GROW=$<BOOL:${HTTPC_GROW}>
    HTTPC_LOGGING=$<BOOL:${HTTPC_LOGGING}>
    HTTPC_CONNECTION_ATTEMPTS=${HTTPC_CONNECTION_ATTEMPTS}u
    HTTPC_REDIRECT_MAX=${HTTPC_REDIRECT_MAX}u
    HTTPC_MAX_HEADER=${HTTPC_MAX_HEADER}ul
    HTTPC_ALLOW_ANY_RESPONSE_STRING=$<BOOL:${HTTPC_ALLOW_ANY_RESPONSE_STRING}>
)
set_property(TARGET httpc_lib PROPERTY C_STANDARD 99)
set_property(TARGET httpc_lib PROPERTY C_STANDARD_REQUIRED ON)
set_property(TARGET httpc_lib PROPERTY C_EXTENSIONS OFF)


set(HTTPC_MAIN_SRCS
    main.c)

add_executable(httpc ${HTTPC_MAIN_SRCS})
target_link_libraries(httpc PRIVATE httpc_lib)
set_property(TARGET httpc PROPERTY C_STANDARD 99)
set_property(TARGET httpc PROPERTY C_STANDARD_REQUIRED ON)
set_property(TARGET httpc PROPERTY C_EXTENSIONS OFF)
