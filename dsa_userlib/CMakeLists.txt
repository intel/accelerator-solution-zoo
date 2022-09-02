#Author: william.wu@intel.com
#Date: 2021/11/10
#History: Created this file for cmake build.

cmake_minimum_required(VERSION 3.8)
project(vector-data-streaming-library)

#SET(CMAKE_BUILD_TYPE "Debug")
set(CMAKE_C_FLAGS_Release "${CMAKE_C_FLAGS_Release} -O3")

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

#add_compile_options(-D__REMOTE_HOST__)
MESSAGE(${CMAKE_SOURCE_DIR})
include_directories(${CMAKE_SOURCE_DIR}/include)

add_subdirectory(src)

#Todo: to add a validation directory which to do unit test
add_subdirectory(test)
