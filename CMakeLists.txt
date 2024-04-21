cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(httpc
    VERSION 4.1.2
    LANGUAGES C)

option(HTTPC_USE_SSL "SSL support" OFF)



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
target_compile_definitions(httpc_lib PUBLIC HTTPC_VERSION="${PROJECT_VERSION}")
set_property(TARGET httpc_lib PROPERTY C_STANDARD 99)
set_property(TARGET httpc_lib PROPERTY C_STANDARD_REQUIRED ON)
set_property(TARGET httpc_lib PROPERTY C_EXTENSIONS OFF)


set(HTTPC_MAIN_SRCS
    main.c)

add_executable(httpc ${HTTPC_MAIN_SRCS})
target_link_libraries(httpc PRIVATE httpc_lib)
set_property(TARGET httpc_lib PROPERTY C_STANDARD 99)
set_property(TARGET httpc_lib PROPERTY C_STANDARD_REQUIRED ON)
set_property(TARGET httpc_lib PROPERTY C_EXTENSIONS OFF)
