cmake_minimum_required(VERSION 3.0)
project(nmp C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "-Wall -Wextra -Wframe-larger-than=4096")
SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS} -g3 -rdynamic -export-dynamic -O0")
SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS} -O2")
set(LIB_TYPE STATIC)

if ($ENV{NMP_SHARED})
    set(LIB_TYPE SHARED)
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -s")
endif ()

add_library(nmp ${LIB_TYPE} nmp.c)
target_link_libraries(nmp uring crypto)

target_include_directories(${PROJECT_NAME} PRIVATE include)
target_include_directories(${PROJECT_NAME} PUBLIC ${PROJECT_SOURCE_DIR})

set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER nmp.h)
install(TARGETS ${PROJECT_NAME})

if (CMAKE_BUILD_TYPE MATCHES Debug)
    set(NMP_DBG_ENV $ENV{NMP_DEBUG})
    if (NOT DEFINED NMP_DBG_ENV)
        set(NMP_DBG_ENV <stdio.h>)
    endif ()

    target_compile_definitions(nmp PRIVATE NMP_DEBUG=${NMP_DBG_ENV})

    # disable timers
    #target_compile_definitions(nmp PRIVATE NMP_DEBUG_TIMERS)
endif ()
