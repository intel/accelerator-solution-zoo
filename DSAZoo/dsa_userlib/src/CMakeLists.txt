project(vector_data_streaming VERSION 1.0.0)

add_compile_options(-Wall)

include_directories(CMAKE_SOURCE_DIR/include)

#set(DSA_SRCS core.c  dsa.c  libaccfg.c  prep.c)
file (GLOB LIB_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/*.c)

add_library (${PROJECT_NAME} SHARED ${LIB_SRCS} )

set(STATIC_LIB "vector_data_streaming_static")
add_library (${STATIC_LIB} STATIC ${LIB_SRCS} )

target_link_libraries(${PROJECT_NAME} PUBLIC accel-config kmod)

