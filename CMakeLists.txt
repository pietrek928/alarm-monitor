cmake_minimum_required(VERSION 3.15...3.27)
project(${SKBUILD_PROJECT_NAME} LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (NOT SKBUILD)
  message(WARNING "\
  This CMake file is meant to be executed using 'scikit-build-core'.
  Running it directly will almost certainly not produce the desired
  result. Prefer: uv sync / pip install .
  ")
endif()

find_package(Python 3.10
  REQUIRED COMPONENTS Interpreter Development.Module
  OPTIONAL_COMPONENTS Development.SABIModule)

find_package(nanobind CONFIG REQUIRED)

nanobind_add_module(
  alarm
  STABLE_ABI
  NB_STATIC
  alarm_monitor/alarm_bindings.cpp
  alarm_monitor/alarm.cc
)

target_include_directories(alarm PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/alarm_monitor)
target_compile_options(alarm PRIVATE -O2 -march=native)

install(TARGETS alarm LIBRARY DESTINATION alarm_monitor)
