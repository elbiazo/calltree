#!/usr/bin/env python3
"""Example: from `main`, get the outgoing call graph and check for a function.

Answers "does <target> appear in main's outgoing calls?" for the
`calltree_sample` fixture. Its outgoing structure is:

    main -> run_all -> chain_a -> chain_b -> chain_c -> leaf_add
                    -> diamond_top -> {diamond_left, diamond_right}
                                   -> diamond_bottom -> leaf_add
                    -> factorial (self)
                    -> ping <-> pong
                    -> leaf_add

So targets like `_chain_c` or `_diamond_bottom` are **not** direct callees of
`main`, but they **are** reachable through the outgoing (callees) call graph.
This script reports both the direct-callee check and the reachability check, and
prints the shortest path that reaches the target.

Run headless (needs a Binary Ninja license + networkx):

    python3 test/python/example_outgoing_reach.py test/build/calltree_sample
    python3 test/python/example_outgoing_reach.py --target _diamond_bottom \
        test/build/calltree_sample

Or from the Binary Ninja GUI console after opening `calltree_sample`:

    exec(open("<path>/test/python/example_outgoing_reach.py").read())
"""

import importlib.util
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.normpath(os.path.join(_HERE, "..", ".."))

# Function to look for. Binary Ninja may show C symbols with a leading underscore
# (e.g. Mach-O), so matching is tolerant of "_chain_c" vs "chain_c". Override on
# the command line with:  --target <name>
DEFAULT_TARGET = "_chain_c"


def _load_api():
    """Import get_call_graph from the installed plugin, or callgraph.py directly."""
    try:
        from calltree import get_call_graph  # type: ignore

        return get_call_graph
    except Exception:
        path = os.path.join(_REPO_ROOT, "callgraph.py")
        spec = importlib.util.spec_from_file_location("calltree_callgraph", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.get_call_graph


def _short(name):
    return name[1:] if name.startswith("_") else name


def _matches(func, want):
    return func is not None and _short(func.name) == _short(want)


def _find(bv, want):
    for candidate in (want, _short(want), "_" + _short(want)):
        matches = bv.get_functions_by_name(candidate)
        if matches:
            return matches[0]
    for func in bv.functions:
        if _matches(func, want):
            return func
    return None


def _parse_args(argv):
    """Return (binary_path_or_None, target). Supports `--target NAME`."""
    target = DEFAULT_TARGET
    path = None
    i = 1
    while i < len(argv):
        arg = argv[i]
        if arg in ("--target", "-t") and i + 1 < len(argv):
            target = argv[i + 1]
            i += 2
            continue
        path = arg
        i += 1
    return path, target


def _get_binary_view(path):
    """Reuse the GUI's `bv` if present, otherwise load the binary headless."""
    gui_bv = globals().get("bv")
    if gui_bv is not None:
        return gui_bv, False

    import binaryninja

    if path is None:
        path = os.path.join(_HERE, "..", "build", "calltree_sample")
    path = os.path.normpath(path)
    if not os.path.isfile(path):
        raise SystemExit(
            f"binary not found: {path}\nBuild it first: "
            "cmake -S test -B test/build && cmake --build test/build"
        )
    print(f"[*] loading {path}")
    loader = getattr(binaryninja, "load", None) or binaryninja.open_view
    view = loader(path)
    view.update_analysis_and_wait()
    return view, True


def main():
    get_call_graph = _load_api()
    path, target = _parse_args(sys.argv)
    bv, opened = _get_binary_view(path)
    try:
        cg = get_call_graph(bv)

        main_func = _find(bv, "main")
        if main_func is None:
            raise SystemExit("could not find `main` in the binary")

        # Build the OUTGOING call graph rooted at main (direction="callees").
        cg.expand(main_func, direction="callees", max_depth=64)
        print("[*]", repr(cg))
        print(f"[*] looking for: {target}")

        # 1) Direct outgoing callees of main.
        direct = cg.callees(main_func)
        print(f"[*] main's direct callees: "
              f"{sorted(_short(f.name) for f in direct if f)}")
        is_direct = any(_matches(f, target) for f in direct)

        # 2) All functions reachable via outgoing calls from main (BFS).
        outgoing = cg.bfs(main_func, direction="callees")
        print(f"[*] main's outgoing (reachable) calls: "
              f"{sorted(_short(f.name) for f in outgoing if f)}")
        is_reachable = any(_matches(f, target) for f in outgoing)

        print()
        print(f"{target} is a DIRECT callee of main?     {is_direct}")
        print(f"{target} exists in main's outgoing calls? {is_reachable}")

        # Show *how* it is reached.
        if is_reachable:
            target_func = _find(bv, target)
            path_funcs = cg.shortest_path(main_func, target_func)
            print("shortest path main -> {}: {}".format(
                target, " -> ".join(_short(f.name) for f in path_funcs)))

        return 0 if is_reachable else 1
    finally:
        if opened:
            f = getattr(bv, "file", None)
            if f is not None and hasattr(f, "close"):
                f.close()


if __name__ == "__main__":
    sys.exit(main())
