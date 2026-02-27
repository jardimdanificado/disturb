cmake_minimum_required(VERSION 3.16)

project(disturb C)

option(DISABLE_IO "Disable IO natives and dynamic FFI calls (embedded profile)" OFF)
option(ENABLE_FFI "Enable Disturb ffi/memory modules" ON)
option(ENABLE_TCC "Enable libtcc integration for TCC-dependent ffi APIs" OFF)

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
  src/ffi.c
)

add_executable(disturb ${DISTURB_SOURCES})

target_include_directories(disturb PRIVATE
  include
  lib/libregexp
  lib
)

set_property(TARGET disturb PROPERTY C_STANDARD 11)
set_property(TARGET disturb PROPERTY C_STANDARD_REQUIRED ON)

if(MSVC)
  # Keep CRT selection consistent with vcpkg x64-windows dependencies (/MD, /MDd)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
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

if(NOT DISABLE_IO)
  target_compile_definitions(disturb PRIVATE DISTURB_ENABLE_IO)
endif()

if(DISABLE_IO)
  target_compile_definitions(disturb PRIVATE DISTURB_EMBEDDED)
  set(ENABLE_FFI OFF CACHE BOOL "" FORCE)
  set(ENABLE_TCC OFF CACHE BOOL "" FORCE)
endif()

if(ENABLE_FFI)
  target_compile_definitions(disturb PRIVATE DISTURB_ENABLE_FFI)

  if(NOT DISABLE_IO)
    target_compile_definitions(disturb PRIVATE DISTURB_ENABLE_FFI_CALLS)

    if(WIN32)
      find_path(FFI_INCLUDE_DIR ffi.h)
      # Multi-config generators (MSVC): select per-config libffi to avoid
      # mixing debug CRT (LIBCMTD) into Release links.
      find_library(FFI_LIBRARY_RELEASE NAMES ffi libffi PATH_SUFFIXES lib)
      find_library(FFI_LIBRARY_DEBUG NAMES ffi libffi PATH_SUFFIXES debug/lib)
      if(NOT FFI_INCLUDE_DIR OR (NOT FFI_LIBRARY_RELEASE AND NOT FFI_LIBRARY_DEBUG))
        message(FATAL_ERROR "ENABLE_FFI=ON with DISABLE_IO=OFF requires libffi (ffi.h + ffi/libffi library).")
      endif()
      target_include_directories(disturb PRIVATE ${FFI_INCLUDE_DIR})
      if(FFI_LIBRARY_RELEASE AND FFI_LIBRARY_DEBUG)
        target_link_libraries(disturb PRIVATE optimized ${FFI_LIBRARY_RELEASE} debug ${FFI_LIBRARY_DEBUG})
      elseif(FFI_LIBRARY_RELEASE)
        target_link_libraries(disturb PRIVATE ${FFI_LIBRARY_RELEASE})
      else()
        target_link_libraries(disturb PRIVATE ${FFI_LIBRARY_DEBUG})
      endif()
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
          message(FATAL_ERROR "ENABLE_FFI=ON with DISABLE_IO=OFF requires libffi (ffi.h + ffi/libffi library).")
        endif()
        target_include_directories(disturb PRIVATE ${FFI_INCLUDE_DIR})
        target_link_libraries(disturb PRIVATE ${FFI_LIBRARY})
      endif()
    endif()
  endif()

  if(ENABLE_TCC)
    set(TCC_VENDOR_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/tinycc")
    find_path(TCC_INCLUDE_DIR libtcc.h
      HINTS "${TCC_VENDOR_DIR}"
    )
    find_library(TCC_LIBRARY NAMES tcc libtcc
      HINTS "${TCC_VENDOR_DIR}" "${TCC_VENDOR_DIR}/lib"
    )
    if(NOT TCC_INCLUDE_DIR OR NOT TCC_LIBRARY)
      message(FATAL_ERROR "ENABLE_TCC=ON requires libtcc (libtcc.h + tcc/libtcc library).")
    endif()
    target_compile_definitions(disturb PRIVATE DISTURB_ENABLE_TCC)
    target_include_directories(disturb PRIVATE ${TCC_INCLUDE_DIR})
    target_link_libraries(disturb PRIVATE ${TCC_LIBRARY})
    if(UNIX)
      get_filename_component(TCC_LIBRARY_DIR ${TCC_LIBRARY} DIRECTORY)
      set_target_properties(disturb PROPERTIES BUILD_RPATH "${TCC_LIBRARY_DIR}")
    endif()
  endif()
endif()

if(UNIX AND NOT APPLE)
  if(NOT DISABLE_IO)
    target_link_libraries(disturb PRIVATE dl)
  endif()
endif()

if(NOT MSVC)
  target_link_libraries(disturb PRIVATE m)
endif()
