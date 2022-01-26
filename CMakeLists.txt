CMAKE_MINIMUM_REQUIRED(VERSION 3.4.0)

project(meta_net)

add_library(meta_net
	src/IServer.cpp
)

target_compile_features(meta_net PRIVATE cxx_std_11)
target_include_directories(meta_net PRIVATE include)
target_include_directories(meta_net PRIVATE include/meta_net)

add_executable(meta_net_test
    test/main.cpp
    src/IServer.cpp
)

target_compile_features(meta_net_test PRIVATE cxx_std_11)
target_include_directories(meta_net_test PRIVATE include)
target_include_directories(meta_net_test PRIVATE include/meta_net)

add_executable(basic_tcp_client_test
    test/basic_tcp_client_test.cpp
    src/IServer.cpp
)

target_compile_features(basic_tcp_client_test PRIVATE cxx_std_11)
target_include_directories(basic_tcp_client_test PRIVATE include)
target_include_directories(basic_tcp_client_test PRIVATE include/meta_net)
