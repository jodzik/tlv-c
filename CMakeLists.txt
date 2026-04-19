cmake_minimum_required(VERSION 3.28)

project(tlv-c)

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} SRC)

if(DEFINED ENV{ZEPHYR_BASE})
    target_sources(app PRIVATE ${SRC})
    target_include_directories(app PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
else()
    add_library(tlv-c STATIC)
    target_sources(tlv-c PRIVATE ${SRC})
    target_include_directories(tlv-c PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
    target_link_libraries(tlv-c PUBLIC safe-c byteorder-c)
endif()
