#!/usr/bin/env python3
"""Validate the Calltree CallGraph API against the compiled fixture binary.

This is an *integration* example: it loads ``calltree_sample`` (built from
``test/src/``) in Binary Ninja and checks that the CallGraph Python API
reproduces the call graph the C++ sources describe (chain, diamond, self and
mutual recursion, aggregating entry point).

Two ways to run it:

1. Headless (needs a Binary Ninja commercial license + networkx)::

       python3 test/python/test_callgraph_api.py /path/to/build/calltree_sample

   If no path is given, common CMake build locations under ``test/`` are tried.

2. From the Binary Ninja GUI Python console, after opening ``calltree_sample``::

       exec(open(".../test/python/test_callgraph_api.py").read())

   The already-open ``bv`` is used automatically.

Expected call graph (see test/src/call_graph.cpp):

    main -> run_all -> { chain_a, diamond_top, factorial, ping, leaf_add }
    chain_a -> chain_b -> chain_c -> leaf_add
    diamond_top -> {diamond_left, diamond_right} -> diamond_bottom -> leaf_add
    factorial -> factorial                       (self recursion)
    ping <-> pong                                (mutual recursion)
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.normpath(os.path.join(_HERE, "..", ".."))


# --------------------------------------------------------------------------- #
# API import: prefer the installed plugin, fall back to loading callgraph.py.
# --------------------------------------------------------------------------- #
def _load_api():
    try:
        from calltree import get_call_graph  # type: ignore

        return get_call_graph
    except Exception:
        import importlib.util

        path = os.path.join(_REPO_ROOT, "callgraph.py")
        spec = importlib.util.spec_from_file_location("calltree_callgraph", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.get_call_graph


# --------------------------------------------------------------------------- #
# BinaryView acquisition: reuse the GUI's `bv`, else load headless.
# --------------------------------------------------------------------------- #
def _default_sample_paths():
    names = ["calltree_sample", "calltree_sample.exe"]
    roots = [
        os.path.join(_HERE, "..", "build"),
        os.path.join(_HERE, ".."),
        os.path.join(_REPO_ROOT, "build"),
        os.getcwd(),
    ]
    out = []
    for root in roots:
        for name in names:
            out.append(os.path.normpath(os.path.join(root, name)))
    return out


def _get_binary_view(argv):
    # In the GUI console, `bv` is already defined in globals.
    gui_bv = globals().get("bv")
    if gui_bv is not None:
        return gui_bv, False

    import binaryninja

    path = argv[1] if len(argv) > 1 else None
    if path is None:
        for candidate in _default_sample_paths():
            if os.path.isfile(candidate):
                path = candidate
                break
    if path is None or not os.path.isfile(path):
        raise SystemExit(
            "could not find calltree_sample; build it first "
            "(cmake -S test -B test/build && cmake --build test/build) "
            "or pass its path as an argument."
        )

    print(f"[*] loading {path}")
    loader = getattr(binaryninja, "load", None) or binaryninja.open_view
    view = loader(path)
    view.update_analysis_and_wait()
    return view, True


# --------------------------------------------------------------------------- #
# Name helpers (tolerant to platform symbol decoration, e.g. leading '_').
# --------------------------------------------------------------------------- #
def _short(name):
    return name[1:] if name.startswith("_") else name


def _find(bv, want):
    matches = bv.get_functions_by_name(want) or bv.get_functions_by_name("_" + want)
    if matches:
        return matches[0]
    for func in bv.functions:
        if _short(func.name) == want:
            return func
    raise AssertionError(f"function not found in binary: {want}")


def _names(funcs):
    return sorted(_short(f.name) for f in funcs if f is not None)


# --------------------------------------------------------------------------- #
# The checks.
# --------------------------------------------------------------------------- #
def run(bv, get_call_graph):
    cg = get_call_graph(bv)

    main = _find(bv, "main")
    run_all = _find(bv, "run_all")
    leaf = _find(bv, "leaf_add")
    chain_a = _find(bv, "chain_a")
    d_top = _find(bv, "diamond_top")
    d_bottom = _find(bv, "diamond_bottom")
    factorial = _find(bv, "factorial")
    ping = _find(bv, "ping")
    pong = _find(bv, "pong")

    cg.expand(main, direction="both", max_depth=12)
    cg.expand(leaf, direction="callers", max_depth=12)
    print("[*]", repr(cg))

    checks = []

    def check(label, ok):
        checks.append((label, bool(ok)))
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}")

    # Entry point wiring.
    check("main calls run_all", "run_all" in _names(cg.callees(main)))
    check(
        "run_all calls every subgraph root",
        set(_names(cg.callees(run_all)))
        >= {"chain_a", "diamond_top", "factorial", "ping", "leaf_add"},
    )

    # Callers of the shared leaf.
    check(
        "leaf_add callers = chain_c, diamond_bottom, run_all",
        _names(cg.callers(leaf)) == ["chain_c", "diamond_bottom", "run_all"],
    )

    # Linear chain reachability + shortest path length.
    check("chain_a reaches leaf_add", cg.reaches(chain_a, leaf))
    sp = cg.shortest_path(chain_a, leaf)
    check(
        "shortest chain_a->leaf_add is chain_a,b,c,leaf_add",
        _names(sp) == ["chain_a", "chain_b", "chain_c", "leaf_add"]
        and _short(sp[0].name) == "chain_a"
        and _short(sp[-1].name) == "leaf_add",
    )

    # Diamond: exactly two simple paths from top to bottom.
    n_paths = sum(1 for _ in cg.all_paths(d_top, d_bottom))
    check("diamond top->bottom has 2 simple paths", n_paths == 2)

    # Self + mutual recursion (cycle handling).
    check("factorial has self-edge", "factorial" in _names(cg.callees(factorial)))
    check("ping<->pong mutual edges",
          "pong" in _names(cg.callees(ping)) and "ping" in _names(cg.callees(pong)))
    check("ping/pong mutually reachable",
          cg.reaches(ping, pong) and cg.reaches(pong, ping))

    # Search + traversal.
    check("search 'diamond' finds all four",
          _names(cg.search("diamond")) ==
          ["diamond_bottom", "diamond_left", "diamond_right", "diamond_top"])
    check("callers-BFS from leaf reaches main",
          "main" in _names(cg.bfs(leaf, direction="callers")))

    passed = sum(1 for _, ok in checks if ok)
    total = len(checks)
    print(f"\n{passed}/{total} checks passed")
    return passed == total


def main():
    get_call_graph = _load_api()
    bv, opened = _get_binary_view(sys.argv)
    try:
        ok = run(bv, get_call_graph)
    finally:
        if opened:
            closer = getattr(bv, "file", None)
            if closer is not None and hasattr(closer, "close"):
                closer.close()
    if not ok:
        raise SystemExit(1)
    print("OK: CallGraph API matches the fixture binary")


if __name__ == "__main__":
    main()
