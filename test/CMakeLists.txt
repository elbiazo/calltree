cmake_minimum_required(VERSION 3.15)
project(calltree_test LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Keep the authored call structure intact so Binary Ninja (and the Calltree
# plugin) see the same graph the sources describe: no inlining, no optimization.
# Flags are selected per compiler so the fixture also builds on MSVC/Windows.
set(CALLTREE_FIXTURE_FLAGS
    $<$<CXX_COMPILER_ID:MSVC>:/Od;/Ob0;/Zi>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0;-fno-inline;-fno-inline-functions;-g>
)

# --- Fixture: the deliberately-structured call graph -----------------------
add_library(calltree_fixture STATIC src/call_graph.cpp)
target_include_directories(calltree_fixture PUBLIC src)
target_compile_options(calltree_fixture PRIVATE ${CALLTREE_FIXTURE_FLAGS})

# --- Sample binary: load THIS in Binary Ninja to test the plugin -----------
add_executable(calltree_sample src/sample_main.cpp)
target_link_libraries(calltree_sample PRIVATE calltree_fixture)
target_compile_options(calltree_sample PRIVATE ${CALLTREE_FIXTURE_FLAGS})

# --- C++ unit tests: prove the fixture behaves as documented ---------------
add_executable(calltree_unit_tests tests/test_call_graph.cpp)
target_link_libraries(calltree_unit_tests PRIVATE calltree_fixture)
target_include_directories(calltree_unit_tests PRIVATE tests)

enable_testing()

# Register each documented test case with CTest for granular results. Keep this
# list in sync with the TEST_CASE(...) names in tests/test_call_graph.cpp.
set(CALLTREE_TEST_CASES
    leaf
    callers_chain
    diamond_paths
    factorial
    mutual_recursion
    run_all
)
foreach(case ${CALLTREE_TEST_CASES})
    add_test(NAME ${case} COMMAND calltree_unit_tests --run ${case})
endforeach()

# Catch-all target that runs the entire C++ suite in one go.
add_test(NAME cpp_suite COMMAND calltree_unit_tests)

# Optional: the standalone (no-Binary-Ninja) Python smoke test of the CallGraph
# logic, wired into CTest when a Python interpreter is available.
find_program(CALLTREE_PYTHON NAMES python3 python)
if(CALLTREE_PYTHON)
    add_test(
        NAME python_standalone_smoke
        COMMAND ${CALLTREE_PYTHON}
                ${CMAKE_CURRENT_SOURCE_DIR}/python/standalone_smoke.py
    )
endif()
