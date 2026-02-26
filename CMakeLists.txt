cmake_minimum_required(VERSION 3.16)

project(disturb C)

option(DISABLE_IO            "Disable IO natives and dynamic FFI calls (embedded profile)" OFF)
option(DISTURB_ENABLE_SIMD     "Compile with SIMD intrinsics (AVX2/SSE/NEON)"             OFF)
option(DISTURB_ENABLE_PARALLEL "Compile thread pool / task module (requires pthreads)"     OFF)
option(DISTURB_ENABLE_GPU      "Compile OpenCL compute module"                             OFF)
option(DISTURB_ENABLE_LTO      "Enable link-time optimisation"                             OFF)
option(DISTURB_ENABLE_PGO_GEN  "PGO: generate profile data"                               OFF)
option(DISTURB_ENABLE_PGO_USE  "PGO: use profile data"                                    OFF)

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

if(DISTURB_ENABLE_PARALLEL)
  list(APPEND DISTURB_SOURCES src/parallel.c)
endif()
if(DISTURB_ENABLE_GPU)
  list(APPEND DISTURB_SOURCES src/gpu.c)
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
  # Keep CRT selection consistent with vcpkg x64-windows dependencies (/MD, /MDd)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
  target_compile_options(disturb PRIVATE /W4 /O2)
  target_compile_definitions(disturb PRIVATE _CRT_SECURE_NO_WARNINGS)
else()
  if(DISABLE_IO)
    target_compile_options(disturb PRIVATE -Os -Wall -Wextra -pedantic)
  else()
    target_compile_options(disturb PRIVATE -O3 -Wall -Wextra -pedantic)
  endif()
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

target_compile_definitions(disturb PRIVATE DISTURB_ENABLE_FFI)

if(DISABLE_IO)
  target_compile_definitions(disturb PRIVATE DISTURB_EMBEDDED)
endif()

# ---- SIMD ---------------------------------------------------------------
if(DISTURB_ENABLE_SIMD)
  target_compile_definitions(disturb PRIVATE DISTURB_ENABLE_SIMD)
  if(NOT MSVC)
    include(CheckCCompilerFlag)
    check_c_compiler_flag(-mavx2 HAS_AVX2)
    check_c_compiler_flag(-msse4.2 HAS_SSE42)
    if(HAS_AVX2)
      target_compile_options(disturb PRIVATE -mavx2 -mfma)
    elseif(HAS_SSE42)
      target_compile_options(disturb PRIVATE -msse4.2)
    endif()
  else()
    target_compile_options(disturb PRIVATE /arch:AVX2)
  endif()
endif()

# ---- Parallelism --------------------------------------------------------
if(DISTURB_ENABLE_PARALLEL)
  target_compile_definitions(disturb PRIVATE DISTURB_ENABLE_PARALLEL)
  find_package(Threads REQUIRED)
  target_link_libraries(disturb PRIVATE Threads::Threads)
endif()

# ---- GPU (OpenCL) -------------------------------------------------------
if(DISTURB_ENABLE_GPU)
  target_compile_definitions(disturb PRIVATE DISTURB_ENABLE_GPU)
  find_package(OpenCL REQUIRED)
  target_link_libraries(disturb PRIVATE OpenCL::OpenCL)
endif()

# ---- LTO ----------------------------------------------------------------
if(DISTURB_ENABLE_LTO)
  include(CheckIPOSupported)
  check_ipo_supported(RESULT ipo_ok)
  if(ipo_ok)
    set_property(TARGET disturb PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
  endif()
endif()

# ---- PGO ----------------------------------------------------------------
if(DISTURB_ENABLE_PGO_GEN AND NOT MSVC)
  target_compile_options(disturb PRIVATE -fprofile-generate)
  target_link_options(disturb PRIVATE -fprofile-generate)
endif()
if(DISTURB_ENABLE_PGO_USE AND NOT MSVC)
  target_compile_options(disturb PRIVATE -fprofile-use -fprofile-correction)
  target_link_options(disturb PRIVATE -fprofile-use)
endif()

if(NOT DISABLE_IO)
  target_compile_definitions(disturb PRIVATE DISTURB_ENABLE_FFI_CALLS)

  if(WIN32)
    find_path(FFI_INCLUDE_DIR ffi.h)
    # Multi-config generators (MSVC): select per-config libffi to avoid
    # mixing debug CRT (LIBCMTD) into Release links.
    find_library(FFI_LIBRARY_RELEASE NAMES ffi libffi PATH_SUFFIXES lib)
    find_library(FFI_LIBRARY_DEBUG NAMES ffi libffi PATH_SUFFIXES debug/lib)
    if(NOT FFI_INCLUDE_DIR OR (NOT FFI_LIBRARY_RELEASE AND NOT FFI_LIBRARY_DEBUG))
      message(FATAL_ERROR "DISABLE_IO=OFF requires libffi (ffi.h + ffi/libffi library) for dynamic FFI calls.")
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
        message(FATAL_ERROR "DISABLE_IO=OFF requires libffi (ffi.h + ffi/libffi library) for dynamic FFI calls.")
      endif()
      target_include_directories(disturb PRIVATE ${FFI_INCLUDE_DIR})
      target_link_libraries(disturb PRIVATE ${FFI_LIBRARY})
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
