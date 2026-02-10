cmake_minimum_required(VERSION 3.16)

project(disturb C)

option(ENABLE_IO "Enable IO natives" ON)
option(ENABLE_FFI "Enable core FFI module" ON)
option(ENABLE_FFI_CALLS "Enable dynamic FFI calls (ffi.load/ffi.bind)" ON)
option(ENABLE_EMBEDDED "Enable embeddable profile (no IO, no dynamic FFI calls, no import)" OFF)

if(ENABLE_EMBEDDED)
  set(ENABLE_IO OFF CACHE BOOL "Enable IO natives" FORCE)
  set(ENABLE_FFI ON CACHE BOOL "Enable core FFI module" FORCE)
  set(ENABLE_FFI_CALLS OFF CACHE BOOL "Enable dynamic FFI calls (ffi.load/ffi.bind)" FORCE)
endif()

set(DISTURB_SOURCES
  lib/libregexp/cutils.c
  lib/libregexp/libunicode.c
  lib/libregexp/libregexp.c
  src/vm.c
  src/bytecode.c
  src/syntax.c
  src/functions.c
  src/papagaio.c
  src/cli.c
)

if(ENABLE_FFI)
  list(APPEND DISTURB_SOURCES src/ffi.c)
endif()

add_executable(disturb ${DISTURB_SOURCES})

target_include_directories(disturb PRIVATE
  include
  lib/libregexp
  lib
)

set_property(TARGET disturb PROPERTY C_STANDARD 11)
set_property(TARGET disturb PROPERTY C_STANDARD_REQUIRED ON)

if(MSVC)
  target_compile_options(disturb PRIVATE /W4 /O2)
  target_compile_definitions(disturb PRIVATE _CRT_SECURE_NO_WARNINGS)
else()
  target_compile_options(disturb PRIVATE -O2 -Wall -Wextra -pedantic)
  set_source_files_properties(
    lib/libregexp/cutils.c
    lib/libregexp/libunicode.c
    lib/libregexp/libregexp.c
    PROPERTIES COMPILE_OPTIONS "-Wno-unused-parameter;-Wno-sign-compare;-Wno-pedantic"
  )
endif()

if(ENABLE_IO)
  target_compile_definitions(disturb PRIVATE DISTURB_ENABLE_IO)
endif()

if(ENABLE_FFI)
  target_compile_definitions(disturb PRIVATE DISTURB_ENABLE_FFI)
endif()

if(ENABLE_EMBEDDED)
  target_compile_definitions(disturb PRIVATE DISTURB_EMBEDDED)
endif()

if(ENABLE_FFI AND ENABLE_FFI_CALLS)
  target_compile_definitions(disturb PRIVATE DISTURB_ENABLE_FFI_CALLS)

  if(WIN32)
    find_path(FFI_INCLUDE_DIR ffi.h)
    find_library(FFI_LIBRARY NAMES ffi libffi)
    if(NOT FFI_INCLUDE_DIR OR NOT FFI_LIBRARY)
      message(FATAL_ERROR "ENABLE_FFI_CALLS=ON requires libffi (ffi.h + ffi/libffi library).")
    endif()
    target_include_directories(disturb PRIVATE ${FFI_INCLUDE_DIR})
    target_link_libraries(disturb PRIVATE ${FFI_LIBRARY})
  else()
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
      pkg_check_modules(FFI QUIET libffi)
    endif()

    if(FFI_FOUND)
      target_include_directories(disturb PRIVATE ${FFI_INCLUDE_DIRS})
      target_link_directories(disturb PRIVATE ${FFI_LIBRARY_DIRS})
      target_link_libraries(disturb PRIVATE ${FFI_LIBRARIES})
      target_compile_options(disturb PRIVATE ${FFI_CFLAGS_OTHER})
    else()
      find_path(FFI_INCLUDE_DIR ffi.h)
      find_library(FFI_LIBRARY NAMES ffi libffi)
      if(NOT FFI_INCLUDE_DIR OR NOT FFI_LIBRARY)
        message(FATAL_ERROR "ENABLE_FFI_CALLS=ON requires libffi (ffi.h + ffi/libffi library).")
      endif()
      target_include_directories(disturb PRIVATE ${FFI_INCLUDE_DIR})
      target_link_libraries(disturb PRIVATE ${FFI_LIBRARY})
    endif()
  endif()
endif()

if(UNIX AND NOT APPLE)
  if(ENABLE_FFI AND ENABLE_FFI_CALLS)
    target_link_libraries(disturb PRIVATE dl)
  endif()
endif()

if(NOT MSVC)
  target_link_libraries(disturb PRIVATE m)
endif()
