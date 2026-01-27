cmake_minimum_required(VERSION 3.28)

project(tlv-c)

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} SRC)

add_library(tlv-c STATIC ${SRC})

target_link_libraries(tlv-c PUBLIC safe-c byteorder-c)
