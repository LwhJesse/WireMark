cmake_minimum_required(VERSION 3.22)
project(WireMark VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)
find_package(PkgConfig QUIET)

if(PkgConfig_FOUND)
  pkg_check_modules(NFQUEUE QUIET libnetfilter_queue)
endif()

set(WIREMARK_NFQ_SOURCE src/nfq_gateway_stub.cpp)
if(NFQUEUE_FOUND)
  set(WIREMARK_NFQ_SOURCE src/nfq_gateway.cpp)
endif()

add_executable(wiremark
  src/main.cpp
  src/crypto.cpp
  src/protocol.cpp
  src/tun.cpp
  src/udp.cpp
  src/logger.cpp
  src/capture.cpp
  src/compact.cpp
  src/tcp.cpp
  src/netif.cpp
  src/packet_policy.cpp
  ${WIREMARK_NFQ_SOURCE}
)

target_include_directories(wiremark PRIVATE include)
target_link_libraries(wiremark PRIVATE OpenSSL::Crypto)
if(NFQUEUE_FOUND)
  target_compile_definitions(wiremark PRIVATE WIREMARK_HAVE_NFQUEUE=1)
  target_include_directories(wiremark PRIVATE ${NFQUEUE_INCLUDE_DIRS})
  target_link_libraries(wiremark PRIVATE ${NFQUEUE_LIBRARIES})
  target_link_directories(wiremark PRIVATE ${NFQUEUE_LIBRARY_DIRS})
endif()
target_compile_options(wiremark PRIVATE -Wall -Wextra -Wpedantic)

install(TARGETS wiremark RUNTIME DESTINATION bin)
