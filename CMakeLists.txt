cmake_minimum_required(VERSION 3.20)
project(soupbin)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wshadow -Wnon-virtual-dtor")

set(CMAKE_CXX_FLAGS_DEBUG "-g -Og -fsanitize=address,undefined -fno-omit-frame-pointer -fsanitize-undefined-trap-on-error")
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "-fsanitize=address,undefined")
set(CMAKE_SHARED_LINKER_FLAGS_DEBUG "-fsanitize=address,undefined")

set(CMAKE_CXX_FLAGS_PROFILE "-g3 -O3 -fno-omit-frame-pointer")
set(CMAKE_EXE_LINKER_FLAGS_PROFILE "")
set(CMAKE_SHARED_LINKER_FLAGS_PROFILE "")

set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
set(CMAKE_EXE_LINKER_FLAGS_RELEASE "-s")
set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "-s")

include(FetchContent)
FetchContent_Declare(
  spdlog
  URL https://github.com/gabime/spdlog/archive/refs/tags/v1.15.3.zip
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(spdlog)

add_library(soupbin STATIC src/server.cpp src/client.cpp src/detail/client_manager.cpp src/detail/session.cpp)
target_include_directories(soupbin PUBLIC include/ PRIVATE src/)
target_link_libraries(soupbin PUBLIC spdlog::spdlog)

add_executable(example_server examples/server.cpp)
target_link_libraries(example_server PRIVATE soupbin)

add_executable(example_client examples/client.cpp)
target_link_libraries(example_client PRIVATE soupbin)
