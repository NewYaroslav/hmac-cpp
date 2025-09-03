cmake_minimum_required(VERSION 3.5)
project(hmac_cpp LANGUAGES CXX)

if(NOT DEFINED CMAKE_CXX_STANDARD)
    set(CMAKE_CXX_STANDARD 11)
endif()
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(BUILD_EXAMPLE "Build the example program" ON)
option(BUILD_TESTS "Build the test suite" OFF)

set(HMAC_SOURCES
    sha1.cpp
	sha256.cpp
    sha512.cpp
        hmac.cpp
        hmac_utils.cpp
)

set(HMAC_HEADERS
    hmac.hpp
    hmac_utils.hpp
    sha1.hpp
    sha256.hpp
    sha512.hpp
)

add_library(hmac STATIC ${HMAC_SOURCES})
target_include_directories(hmac PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

if(BUILD_EXAMPLE)
    add_executable(example example.cpp)
    target_link_libraries(example PRIVATE hmac)
    target_include_directories(example PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
endif()

install(TARGETS hmac DESTINATION lib)
install(FILES ${HMAC_HEADERS} DESTINATION include/hmac_cpp)

if(BUILD_TESTS)
    enable_testing()
    include(FetchContent)
    FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/refs/heads/main.zip
    )
    FetchContent_MakeAvailable(googletest)
    add_executable(test_all test_all.cpp)
    target_link_libraries(test_all PRIVATE hmac gtest_main)
    target_include_directories(test_all PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    add_test(NAME test_all COMMAND test_all)
endif()
