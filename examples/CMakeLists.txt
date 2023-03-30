set(examples
        file_transfer
        message)

foreach (item ${examples})
    add_executable(${item} ${item}.c common.c)
    target_link_libraries(${item} nmp)
endforeach ()

target_link_libraries(message pthread)
