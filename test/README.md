# Calltree tests

A CMake C++ project that builds a small binary with a **deliberately-known call
graph**, plus tests that validate both the C++ fixture and the plugin's
`CallGraph` Python API against it.

```
test/
├── CMakeLists.txt
├── src/                     # the fixture call graph (compiled -O0 -fno-inline)
│   ├── call_graph.hpp
│   ├── call_graph.cpp
│   └── sample_main.cpp      # -> builds the `calltree_sample` binary
├── tests/                   # zero-dependency C++ unit tests (CTest)
│   ├── test_framework.hpp
│   └── test_call_graph.cpp
└── python/                  # Python examples for the CallGraph API
    ├── standalone_smoke.py  # no Binary Ninja required
    └── test_callgraph_api.py# loads calltree_sample in Binary Ninja
```

## The fixture call graph

Defined in [`src/call_graph.cpp`](src/call_graph.cpp) with C linkage so Binary
Ninja shows clean symbol names:

```
main ──► run_all ──► chain_a ──► chain_b ──► chain_c ──► leaf_add
                │                                          ▲  ▲
                ├──► diamond_top ─► diamond_left ─► diamond_bottom
                │               └─► diamond_right ┘
                ├──► factorial ─┐          (self recursion)
                │        ▲──────┘
                ├──► ping ⇄ pong           (mutual recursion / A→B→A cycle)
                └──► leaf_add
```

It intentionally covers a leaf, a linear chain, a diamond (two distinct paths),
self recursion, and a mutual-recursion cycle so every part of the API is
exercised.

## Building & running the C++ tests

Requires CMake (>= 3.15) and a C++17 compiler.

```bash
cmake -S test -B test/build
cmake --build test/build
ctest --test-dir test/build --output-on-failure
```

This produces:

* **`test/build/calltree_sample`** — the fixture binary to open in Binary Ninja.
* **`test/build/calltree_unit_tests`** — the C++ unit tests. Run all with no
  args, one with `--run <case>`, or list them with `--list`.

CTest registers each documented case (`leaf`, `callers_chain`, `diamond_paths`,
`factorial`, `mutual_recursion`, `run_all`), a full `cpp_suite`, and
`python_standalone_smoke` (below, when a Python interpreter is found).

## Python examples

### `standalone_smoke.py` — no Binary Ninja needed

Rebuilds the same call graph with stub `Function`/`BinaryView` objects and
exercises the entire `CallGraph` API (only `networkx` is required):

```bash
python3 test/python/standalone_smoke.py
```

### `test_callgraph_api.py` — against the real binary

Loads `calltree_sample` in Binary Ninja and asserts the extracted graph matches
the documented structure. Needs a Binary Ninja commercial license (headless) and
`networkx` installed in Binary Ninja's Python.

```bash
# Headless:
python3 test/python/test_callgraph_api.py test/build/calltree_sample

# Or, in the Binary Ninja GUI console after opening calltree_sample:
exec(open("<path>/test/python/test_callgraph_api.py").read())
```

### `example_outgoing_reach.py` — "is X in main's outgoing calls?"

A focused example: builds the outgoing call graph from `main` and checks whether
a target function (default `_chain_c`) appears in it, printing the direct-callee
check, the reachability check, and the shortest path that reaches it. Override
the target with `--target`:

```bash
python3 test/python/example_outgoing_reach.py test/build/calltree_sample
python3 test/python/example_outgoing_reach.py --target _diamond_bottom \
    test/build/calltree_sample
```

Symbol matching is tolerant of a leading underscore, so `_chain_c` and `chain_c`
both work.

## Fixture → CallGraph API mapping

| Fixture structure          | Validates                                              |
|----------------------------|--------------------------------------------------------|
| `main -> run_all -> ...`   | `callees()` / entry-point wiring                       |
| callers of `leaf_add`      | `callers()` (predecessors)                             |
| `chain_a … leaf_add`       | `reaches()`, `shortest_path()` (length 4)              |
| diamond top→bottom         | `all_paths()` (exactly 2 simple paths)                 |
| `factorial` self-call      | cycle-safe `expand()`, self-edge in `callees()`        |
| `ping ⇄ pong`              | A→B→A cycle handling, mutual `reaches()`               |
| `diamond_*`, `chain_*`     | `search()` (substring / regex)                         |
| callers-direction BFS      | `bfs(direction="callers")` reaches `main`              |
