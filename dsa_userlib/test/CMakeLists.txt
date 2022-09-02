project(dsa_test)

include_directories("${CMAKE_SOURCE_DIR}/include")

set(TEST_SRC dsa_test.c)
add_executable(${PROJECT_NAME} ${TEST_SRC})
target_link_libraries(${PROJECT_NAME} vector_data_streaming)

project(dsa_mt_single)
set(TEST_SRC1 dsa_mt_single.c)
add_executable(${PROJECT_NAME} ${TEST_SRC1})
target_link_libraries(${PROJECT_NAME} vector_data_streaming pthread)

project(dsa_test_batch)
set(TEST_SRC2 dsa_test_batch.c)
add_executable(${PROJECT_NAME} ${TEST_SRC2})
target_link_libraries(${PROJECT_NAME} vector_data_streaming)


project(dsa_test_vector)
set(TEST_SRC3 dsa_test_vector.c)
add_executable(${PROJECT_NAME} ${TEST_SRC3})
target_link_libraries(${PROJECT_NAME} vector_data_streaming)

project(dsa_mt_vector)
set(TEST_SRC3 dsa_mt_vector.c)
add_executable(${PROJECT_NAME} ${TEST_SRC3})
target_link_libraries(${PROJECT_NAME} vector_data_streaming pthread)


project(dsa_mt_async)
set(TEST_SRC3 dsa_mt_async.c)
add_executable(${PROJECT_NAME} ${TEST_SRC3})
target_link_libraries(${PROJECT_NAME} vector_data_streaming pthread)
