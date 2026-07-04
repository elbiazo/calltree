# Calltree

Author: **Eric Biazo**

Calltree generator for function

## Description:

Generates call tree. Alternative view for callgraph.

## Releases

* 3.0 -- Graph-backed call data + Python API (`networkx`)
* 2.1 -- Bug Fix
* 2.0 -- Multiview Support
* 1.2 -- Bug Fixes
* 1.1 -- Refactoring
* 1.0 -- Public Release
* 0.0 -- Beta Release

## Minimum Version

This plugin requires the following minimum version of Binary Ninja:

 * 2966

## License

This plugin is released under an [MIT license](./LICENSE).

## Caution

When working with really big binaries with alot of xrefs, you would want to change recursive depth to smaller number or else Binary Ninja might hang.
## Description

Calltree is a plugin that generates call tree for a function. It is an alternative view for callgraph. It is a multiview plugin, so you can have multiple calltree views open at the same time.

### Default View

![](images/2023-03-06-23-31-27.png)

### Expand and Collapse tree

**Expand**

![](images/2023-03-06-23-44-02.png)

**Collapse**

![](images/2023-03-06-23-44-24.png)

**Search**

![](images/2022-02-09-16-53-33.png)

### Recursion Depth

**Show Only Root Level**

![](images/2022-02-09-16-57-21.png)

**Default Recursion Depth in Setting**

![](images/2022-02-09-16-59-03.png)

### Pinning and Removing Calltree View

**Pinning Calltree View**

![](images/2023-03-06-23-40-42.png)

**Pinned Calltree Name Max Length**

![](images/2023-03-06-23-46-04.png)


## Python API

As of `3.0`, the caller/callee relationships are backed by a real graph
(`networkx.DiGraph`) that is decoupled from the UI, so you can query the call
graph programmatically from the Binary Ninja Python console. Nodes are function
start addresses and every edge points from a **caller** to a **callee**.

The graph is expanded lazily around a function and cached per `BinaryView`, so it
stays cheap even on large binaries.

```python
from calltree import get_call_graph

# `bv` is the current BinaryView. `cg` is cached per BinaryView.
cg = get_call_graph(bv)

main = bv.get_functions_by_name("main")[0]

# Grow the graph around a function (direction: "callees", "callers" or "both").
cg.expand(main, direction="both", max_depth=6)

# --- Queries ---
cg.callees(main)          # functions main calls
cg.callers("malloc")      # functions that call malloc (accepts Function/addr/name)

# --- Search (substring by default; regex + mangled-name options available) ---
cg.search("alloc")
cg.search(r"^str.*cpy$", regex=True)

# --- Path finding ---
cg.reaches("main", "system")          # bool: can main reach system?
cg.shortest_path("main", "system")    # [Function, ...]
for path in cg.all_paths("main", "system", cutoff=8):
    print([f.name for f in path])

# --- Traversal ---
for func in cg.bfs(main, direction="callees", max_depth=3):
    print(func.name)

# --- Export ---
cg.to_networkx()   # the underlying networkx.DiGraph
cg.to_dict()       # serializable {"nodes": [...], "edges": [...]}
cg.to_edge_list()  # [(caller_addr, callee_addr), ...]
```

This plugin depends on [`networkx`](https://networkx.org/). Installing via the
Binary Ninja plugin manager installs it automatically from `requirements.txt`; for
manual installs, use the `Install python3 module` command palette action or
`pip install networkx` against Binary Ninja's interpreter.

### Manual / development checkouts

If you cloned this repo straight into your Binary Ninja `plugins/` folder (instead
of installing through the plugin manager), `requirements.txt` is **not** installed
automatically, so you must add `networkx` to Binary Ninja's Python yourself:

* **Easiest:** command palette (`CTRL/CMD-P`) → `Install python3 module` → enter
  `networkx`.
* **From a shell**, install into Binary Ninja's user `pythonXY` folder, e.g. on
  macOS with the bundled Python 3.10:

  ```bash
  pip3 install --target \
    "$HOME/Library/Application Support/Binary Ninja/python310" networkx
  ```

  (Linux uses `~/.binaryninja/pythonXY`; Windows uses
  `%APPDATA%\Binary Ninja\pythonXY`.)

**Restart Binary Ninja** afterwards — the plugin imports `networkx` at load time,
so a running instance won't pick it up until relaunched. Without it, the call
trees render empty and an error is logged.

## Architecture

For a detailed design overview — modules, the call-graph data model, the threading
model, lazy rendering, search, dirty-tracking, and key control flows — see
[`doc/architecture.md`](doc/architecture.md).

## Contributors

Thanks everyone that have contributed to calltree!

* galenbwill
* droogie
* bambu
* crimsonskylark
* SilentVoid13
