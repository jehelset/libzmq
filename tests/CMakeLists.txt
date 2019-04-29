# CMake build script for ZeroMQ tests
cmake_minimum_required(VERSION "2.8.1")

# On Windows: solution file will be called tests.sln
project(tests)

set(tests test_security_sspi)

find_program(CAPSH_PROGRAM NAMES capsh)

if (CAPSH_PROGRAM)
    list(APPEND tests
        test_pair_tcp_cap_net_admin
        )
else()
    message(STATUS "capsh not found, skipping tests that require CAP_NET_ADMIN")
endif()

# add location of platform.hpp for Windows builds
if(WIN32)
  add_definitions(-DZMQ_CUSTOM_PLATFORM_HPP)
  add_definitions(-D_WINSOCK_DEPRECATED_NO_WARNINGS)
  # Same name on 64bit systems
  link_libraries(ws2_32.lib)
  link_libraries(NetApi32.lib)
endif()

add_library(unity STATIC
  "${CMAKE_CURRENT_LIST_DIR}/../external/unity/unity.c"
  "${CMAKE_CURRENT_LIST_DIR}/../external/unity/unity.h"
  "${CMAKE_CURRENT_LIST_DIR}/../external/unity/unity_internals.h")
set_target_properties(unity PROPERTIES
  PUBLIC_HEADER "${CMAKE_CURRENT_LIST_DIR}/../external/unity/unity.h")
target_compile_definitions(unity PUBLIC "UNITY_USE_COMMAND_LINE_ARGS" "UNITY_EXCLUDE_FLOAT")
target_include_directories(unity PUBLIC "${CMAKE_CURRENT_LIST_DIR}/../external/unity")

if(MSVC_VERSION LESS 1700)
  set_source_files_properties("${CMAKE_CURRENT_LIST_DIR}/../external/unity/unity.c" PROPERTIES LANGUAGE CXX)
endif()

if(MSVC_VERSION LESS 1600)
  target_compile_definitions(unity PUBLIC "UNITY_EXCLUDE_STDINT_H")
endif()

# add library and include dirs for all targets
if(BUILD_SHARED)
  link_libraries(libzmq ${OPTIONAL_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} unity)
else()
  link_libraries(libzmq-static ${OPTIONAL_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} unity)
endif()
include_directories("${ZeroMQ_SOURCE_DIR}/../include" "${ZeroMQ_BINARY_DIR}")

foreach(test ${tests})
  # target_sources not supported before CMake 3.1
  if(ZMQ_HAVE_CURVE AND ${test} MATCHES test_security_curve)
    add_executable(${test} ${test}.cpp
      "../src/tweetnacl.c"
      "../src/err.cpp"
      "../src/random.cpp"
      "../src/clock.cpp"
      "testutil_security.hpp")
  elseif(${test} MATCHES test_security_zap)
    add_executable(${test} ${test}.cpp
      "testutil_security.hpp")
  else()
    add_executable(${test} ${test}.cpp "testutil.hpp" "testutil_unity.hpp" "testutil_monitoring.hpp")
  endif()
  if(WIN32)
    # This is the output for Debug dynamic builds on Visual Studio 6.0
    # You should provide the correct directory, don't know how to do it automatically
    find_path(LIBZMQ_PATH "libzmq.lib" PATHS "../bin/Win32/Debug/v120/dynamic")
    if(NOT ${LIBZMQ_PATH} STREQUAL "LIBZMQ_PATH-NOTFOUND")
      set_target_properties(${test} PROPERTIES LINK_FLAGS "/LIBPATH:${LIBZMQ_PATH}")
    endif()
  else()
    # per-test directories not generated on OS X / Darwin
    if(NOT ${CMAKE_CXX_COMPILER_ID} MATCHES "Clang.*")
      link_directories(${test} PRIVATE "${ZeroMQ_SOURCE_DIR}/../lib")
    endif()
  endif()

  if(RT_LIBRARY)
    target_link_libraries(${test} ${RT_LIBRARY})
  endif()
  if(WIN32)
    add_test(NAME ${test} WORKING_DIRECTORY ${LIBRARY_OUTPUT_PATH} COMMAND ${test})
  else()
    if (${test} MATCHES "_cap_net_admin")
      add_test(NAME ${test} COMMAND sh -c "sudo ${CAPSH_PROGRAM} --caps=cap_net_admin+eip -- -c $<TARGET_FILE:${test}>")
    else()
      add_test(NAME ${test} COMMAND ${test})
    endif()
  endif()
  set_tests_properties(${test} PROPERTIES TIMEOUT 10)
  set_tests_properties(${test} PROPERTIES SKIP_RETURN_CODE 77)
endforeach()

#Check whether all tests in the current folder are present
file(READ "${CMAKE_CURRENT_LIST_FILE}" CURRENT_LIST_FILE_CONTENT)
file(GLOB ALL_TEST_SOURCES "test_*.cpp")
#foreach(TEST_SOURCE ${ALL_TEST_SOURCES})
  #get_filename_component(TESTNAME "${TEST_SOURCE}" NAME_WE)
  #string(REGEX MATCH "${TESTNAME}" MATCH_TESTNAME "${CURRENT_LIST_FILE_CONTENT}")
  #if(NOT MATCH_TESTNAME)
    #message(AUTHOR_WARNING "Test '${TESTNAME}' is not known to CTest.")
  #endif()
#endforeach()
