cmake_minimum_required(VERSION 3.5)
project(c2_client C)

set(CMAKE_C_STANDARD 99)

set(SERVER_IP "127.0.0.1")
set(SERVER_PORT 4444)
set(BUFFER_SIZE 512)
set(DB_PATH "client_events.db")

configure_file(config.h.in config.h)

find_package(SQLite3 REQUIRED)
include_directories(${SQLite3_INCLUDE_DIRS})

add_executable(c2_client c2_client.c sql_manager.c)
target_include_directories(c2_client PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(c2_client ${SQLite3_LIBRARIES})
