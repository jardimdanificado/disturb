cmake_minimum_required(VERSION 3.16)

project(papagaio C)

option(DISABLE_SYSTEM "Disable system-dependent features (IO, import, dynamic FFI calls)" OFF)
option(DISABLE_FFI_CALLS "Disable dynamic FFI calls (libffi/dlopen) even when system features are enabled" OFF)

set(PAPAGAIO_SOURCES
  src/vm.c
  src/bytecode.c
  src/syntax.c
  src/functions.c
  src/host_io.c
  src/papagaio_wasm.c
  src/papagaio.c
  src/cli.c
  src/ffi.c
)

add_executable(papagaio ${PAPAGAIO_SOURCES})
target_compile_definitions(papagaio PRIVATE DISTURB_ENABLE_FFI)

target_include_directories(papagaio PRIVATE
  include
)

set_property(TARGET papagaio PROPERTY C_STANDARD 11)
set_property(TARGET papagaio PROPERTY C_STANDARD_REQUIRED ON)

if(MSVC)
  # Keep CRT selection consistent with vcpkg x64-windows dependencies (/MD, /MDd)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
  target_compile_options(papagaio PRIVATE /W4 /O2)
  target_compile_definitions(papagaio PRIVATE _CRT_SECURE_NO_WARNINGS)
else()
  target_compile_options(papagaio PRIVATE -O2 -Wall -Wextra -pedantic)
endif()

if(NOT DISABLE_SYSTEM)
  target_compile_definitions(papagaio PRIVATE DISTURB_ENABLE_IO)
  if(NOT DISABLE_FFI_CALLS)
    target_compile_definitions(papagaio PRIVATE DISTURB_ENABLE_FFI_CALLS)
  endif()
else()
  target_compile_definitions(papagaio PRIVATE DISTURB_EMBEDDED)
endif()

if(NOT DISABLE_SYSTEM AND NOT DISABLE_FFI_CALLS)
  if(WIN32)
    find_path(FFI_INCLUDE_DIR ffi.h)
    # Multi-config generators (MSVC): select per-config libffi to avoid
    # mixing debug CRT (LIBCMTD) into Release links.
    find_library(FFI_LIBRARY_RELEASE NAMES ffi libffi PATH_SUFFIXES lib)
    find_library(FFI_LIBRARY_DEBUG NAMES ffi libffi PATH_SUFFIXES debug/lib)
    if(NOT FFI_INCLUDE_DIR OR (NOT FFI_LIBRARY_RELEASE AND NOT FFI_LIBRARY_DEBUG))
      message(FATAL_ERROR "DISABLE_SYSTEM=OFF requires libffi (ffi.h + ffi/libffi library).")
    endif()
    target_include_directories(papagaio PRIVATE ${FFI_INCLUDE_DIR})
    if(FFI_LIBRARY_RELEASE AND FFI_LIBRARY_DEBUG)
      target_link_libraries(papagaio PRIVATE optimized ${FFI_LIBRARY_RELEASE} debug ${FFI_LIBRARY_DEBUG})
    elseif(FFI_LIBRARY_RELEASE)
      target_link_libraries(papagaio PRIVATE ${FFI_LIBRARY_RELEASE})
    else()
      target_link_libraries(papagaio PRIVATE ${FFI_LIBRARY_DEBUG})
    endif()
  else()
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
      pkg_check_modules(FFI QUIET libffi)
    endif()

    if(FFI_FOUND)
      target_include_directories(papagaio PRIVATE ${FFI_INCLUDE_DIRS})
      target_link_directories(papagaio PRIVATE ${FFI_LIBRARY_DIRS})
      target_link_libraries(papagaio PRIVATE ${FFI_LIBRARIES})
      target_compile_options(papagaio PRIVATE ${FFI_CFLAGS_OTHER})
    else()
      find_path(FFI_INCLUDE_DIR ffi.h)
      find_library(FFI_LIBRARY NAMES ffi libffi)
      if(NOT FFI_INCLUDE_DIR OR NOT FFI_LIBRARY)
        message(FATAL_ERROR "DISABLE_SYSTEM=OFF requires libffi (ffi.h + ffi/libffi library).")
      endif()
      target_include_directories(papagaio PRIVATE ${FFI_INCLUDE_DIR})
      target_link_libraries(papagaio PRIVATE ${FFI_LIBRARY})
    endif()
  endif()
endif()

if(UNIX AND NOT APPLE)
  if(NOT DISABLE_SYSTEM AND NOT DISABLE_FFI_CALLS)
    target_link_libraries(papagaio PRIVATE dl)
  endif()
endif()

if(NOT MSVC)
  target_link_libraries(papagaio PRIVATE m)
endif()
