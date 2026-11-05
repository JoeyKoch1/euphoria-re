cmake_minimum_required(VERSION 3.20)
project(euphoria LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_compile_options($<$<COMPILE_LANGUAGE:C,CXX>:-Wall> $<$<COMPILE_LANGUAGE:C,CXX>:-Wextra>)

add_library(eu_simd STATIC simd/scan.c)
target_include_directories(eu_simd PUBLIC simd)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64)$")
  enable_language(ASM_NASM)
  target_sources(eu_simd PRIVATE simd/scan_avx2.asm)
  target_compile_definitions(eu_simd PUBLIC EU_HAVE_AVX2)
endif()

add_library(eu_db STATIC db/db.c)
target_include_directories(eu_db PUBLIC db capi)

add_library(eu_core STATIC core/session.cpp)
target_link_libraries(eu_core PRIVATE eu_db eu_simd)

install(TARGETS eu_core eu_db eu_simd ARCHIVE DESTINATION lib)

enable_testing()
add_executable(scan_test EXCLUDE_FROM_ALL simd/scan_test.c)
target_link_libraries(scan_test PRIVATE eu_simd)
add_test(NAME scan_test COMMAND scan_test)
Cwel
