add_library(protocols ethernet.c ipv4.c)
target_include_directories(protocols PUBLIC ${CMAKE_CURRENT_LIST_DIR})