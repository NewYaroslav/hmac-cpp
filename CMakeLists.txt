cmake_minimum_required(VERSION 3.5)
project(hmac_cpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(BUILD_EXAMPLE "Build the example program" ON)

set(HMAC_HEADERS
    hmac.hpp
	hmac_timed_token.hpp
    sha256.hpp
    sha512.hpp
)

set(HMAC_SOURCES
    sha256.cpp
    sha512.cpp
	hmac.cpp
	hmac_timed_token.cpp
)

add_library(hmac STATIC ${HMAC_SOURCES} ${HMAC_HEADERS})
target_include_directories(hmac PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

if(BUILD_EXAMPLE)
    add_executable(example example.cpp)
    target_link_libraries(example PRIVATE hmac)
    target_include_directories(example PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
endif()

install(TARGETS hmac DESTINATION lib)
install(FILES ${HMAC_HEADERS} DESTINATION include/hmac_cpp)