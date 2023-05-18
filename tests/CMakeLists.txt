set(ab_tests
        hello_world
        hello_world_na
        hello_world_alloc
        hello_world_early
        ordering
        queues
        include_lost
        connect_payload
        io_uring_enobufs
        corrupted_response
        )

set(unit_sets
        u_msg
        u_noise
        u_noise2
        u_hashtable
        u_pktval
        )


string(LENGTH "${PROJECT_SOURCE_DIR}/" TEST_SRC_OFFSET)
add_compile_definitions(SRC_PATH_OFFSET=${TEST_SRC_OFFSET})

add_library(test_noops SHARED test_noops.c)
target_link_libraries(test_noops nmp)

foreach (item ${ab_tests})
    add_executable(${item} ${item}.c test_drv.c)
    target_link_libraries(${item} test_noops)

    add_test(NAME ${item} COMMAND ${item})
endforeach ()


foreach (item ${unit_sets})
    add_executable(${item} ${item}.c)
    target_include_directories(${item} PRIVATE ${PROJECT_SOURCE_DIR})
    target_link_libraries(${item} uring crypto)

    add_test(NAME ${item} COMMAND ${item})
endforeach ()
