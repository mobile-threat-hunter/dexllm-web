cmake_minimum_required(VERSION 3.20)
project(dexllm_wasm LANGUAGES CXX)

# Single-threaded WASM build for the dexllm-web GitHub Pages demo. -pthread
# is intentionally OFF — the vendored DexKit ThreadPool has an Emscripten-
# guarded shim (vendor/dexkit_core/Core/third_party/thread_helper/ThreadPool.h)
# that runs tasks inline when __EMSCRIPTEN__ && !__EMSCRIPTEN_PTHREADS__.
#
# Configure with:
#   emcmake cmake -B build -DDEXLLM_ROOT=/path/to/dexllm
#   cmake --build build --parallel
#
# Outputs: build/dexllm.js + build/dexllm.wasm — copy into dexllm-web/.

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT DEFINED DEXLLM_ROOT)
    message(FATAL_ERROR "Pass -DDEXLLM_ROOT=/abs/path/to/dexllm")
endif()
get_filename_component(DEXLLM_ROOT "${DEXLLM_ROOT}" ABSOLUTE)

set(DEXKIT_CORE_ROOT "${DEXLLM_ROOT}/vendor/dexkit_core")
if(NOT EXISTS "${DEXKIT_CORE_ROOT}/Core/CMakeLists.txt")
    message(FATAL_ERROR "DexKit Core not found at ${DEXKIT_CORE_ROOT}/Core")
endif()

add_subdirectory("${DEXKIT_CORE_ROOT}/Core" dexkit_core_build EXCLUDE_FROM_ALL)

# C++ exceptions must be enabled on EVERY object file that touches a try/catch
# OR a throw site. Otherwise emscripten compiles those translation units with
# the default "no exceptions" mode, where try/catch becomes a no-op and a
# thrown std::exception escapes as an unrecoverable wasm trap. The native
# python build uses libstdc++ which throws normally, so the dexllm-internal
# guards (3× try/catch wrapping std::stoi calls) work there; under wasm
# without -fexceptions, the catches silently miss and a "stoi: no conversion"
# from a stray "vN" register name on a complex class (e.g. La2dp/Vol/ALauncher;)
# propagates all the way to the JS binding as a CppException.
# Apply to the vendored static lib too — its slicer throws SLICER_CHECK errors
# as std::runtime_error that dexllm catches in the binding.
foreach(tgt dexkit_static)
  if(TARGET ${tgt})
    target_compile_options(${tgt} PRIVATE -fexceptions)
  endif()
endforeach()

# dexkit_ext — same source list as DEXLLM_ROOT/CMakeLists.txt
add_library(dexkit_ext STATIC
    "${DEXLLM_ROOT}/native/core_ext/dexkit_ext.cpp"
    "${DEXLLM_ROOT}/native/core_ext/dexitem_code_source.cpp"
    "${DEXLLM_ROOT}/native/core_ext/dex_verifier.cpp"
    "${DEXLLM_ROOT}/native/core_ext/analysis.cpp"
)
target_include_directories(dexkit_ext PUBLIC
    "${DEXLLM_ROOT}/native/core_ext/include"
    "${DEXLLM_ROOT}/native/dad_cpp/include"
)
target_link_libraries(dexkit_ext PUBLIC dexkit_static)
target_compile_options(dexkit_ext PRIVATE -fexceptions)

# web_engine — the IoC / content-provider / capability ports, vendored from
# dexllm c3ec1a1 (see vendor/include/web_analysis.h). dexllm 4b085d8 dropped
# these from its core because only this web build consumed them, so they live
# here now. Kept a SEPARATE target so dexkit_ext above stays a faithful mirror
# of dexllm's own source list.
add_library(web_engine STATIC
    "${CMAKE_CURRENT_SOURCE_DIR}/vendor/ioc.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/vendor/public_suffix.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/vendor/web_analysis.cpp"
)
target_include_directories(web_engine PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/vendor/include"
)
target_link_libraries(web_engine PUBLIC dexkit_ext)
target_compile_options(web_engine PRIVATE -fexceptions)

# dexkit_dad — same source list as DEXLLM_ROOT/CMakeLists.txt
add_library(dexkit_dad STATIC
    "${DEXLLM_ROOT}/native/dad_cpp/decompiler.cpp"
    "${DEXLLM_ROOT}/native/dad_cpp/mutf8.cpp"
    "${DEXLLM_ROOT}/native/dad_cpp/util.cpp"
    "${DEXLLM_ROOT}/native/dad_cpp/node.cpp"
    "${DEXLLM_ROOT}/native/dad_cpp/basic_blocks.cpp"
    "${DEXLLM_ROOT}/native/dad_cpp/graph.cpp"
    "${DEXLLM_ROOT}/native/dad_cpp/instruction.cpp"
    "${DEXLLM_ROOT}/native/dad_cpp/opcode_ins.cpp"
    "${DEXLLM_ROOT}/native/dad_cpp/dataflow.cpp"
    "${DEXLLM_ROOT}/native/dad_cpp/control_flow.cpp"
    "${DEXLLM_ROOT}/native/dad_cpp/dast.cpp"
    "${DEXLLM_ROOT}/native/dad_cpp/writer.cpp"
    "${DEXLLM_ROOT}/native/dad_cpp/decompile.cpp"
    "${DEXLLM_ROOT}/native/dad_cpp/method_snapshot_builder.cpp"
    "${DEXLLM_ROOT}/native/dad_cpp/mock_code_source.cpp"
    "${DEXLLM_ROOT}/native/dad_cpp/instruction_dispatch.cpp"
    "${DEXLLM_ROOT}/native/dad_cpp/instruction_accept.cpp"
)
target_include_directories(dexkit_dad PUBLIC
    "${DEXLLM_ROOT}/native/dad_cpp/include"
)
target_link_libraries(dexkit_dad PUBLIC dexkit_ext)
target_compile_options(dexkit_dad PRIVATE -fexceptions)

# Embind binding (this file).
add_executable(dexllm wasm_module.cpp)
target_link_libraries(dexllm PRIVATE dexkit_ext dexkit_dad web_engine)

# Single-threaded, ES module, modularised, growable memory, zlib for apk
# central-directory deflate, exceptions for the slicer's SLICER_CHECK throws.
target_compile_options(dexllm PRIVATE
    -fexceptions
    -O3
    -Wno-narrowing
)
target_link_options(dexllm PRIVATE
    -lembind
    -fexceptions
    -O3
    "SHELL:-s MODULARIZE=1"
    "SHELL:-s EXPORT_NAME=createDexllm"
    "SHELL:-s EXPORTED_RUNTIME_METHODS=['FS','getExceptionMessage']"
    "SHELL:-s FORCE_FILESYSTEM=1"
    "SHELL:-s ALLOW_MEMORY_GROWTH=1"
    "SHELL:-s USE_ZLIB=1"
    "SHELL:-s STACK_SIZE=16MB"    # bumped from 4MB after some classes (eg La2dp/Vol/ALauncher;) hit stack-overflow during decompile; emit walk caps at 2000 frames but variable splitting / register propagation can recurse deeper on complex graphs
)

# Output .js next to .wasm (Emscripten default). No -sENVIRONMENT restriction
# so the build also runs under node for offline smoke tests.
set_target_properties(dexllm PROPERTIES SUFFIX ".js")
