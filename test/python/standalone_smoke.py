#!/usr/bin/env python3
"""Standalone smoke test for the Calltree CallGraph API — no Binary Ninja needed.

This mirrors the fixture call graph defined in ``test/src/call_graph.cpp`` using
lightweight stub objects that quack like Binary Ninja ``Function`` / ``BinaryView``
objects. It exercises the whole ``CallGraph`` Python API (expand, queries, search,
path-finding, traversal, export, caching, cycle-safety) so you can validate the
graph logic anywhere ``networkx`` is installed.

Run directly::

    python3 test/python/standalone_smoke.py

or via CTest (registered automatically by test/CMakeLists.txt)::

    ctest -R python_standalone_smoke --output-on-failure
"""

import importlib.util
import os
import sys

# Locate callgraph.py at the repository root (two levels up from this file) and
# import it directly, so we don't need Binary Ninja to have loaded the plugin.
_HERE = os.path.dirname(os.path.abspath(__file__))
_CALLGRAPH_PY = os.path.normpath(os.path.join(_HERE, "..", "..", "callgraph.py"))

_spec = importlib.util.spec_from_file_location("calltree_callgraph", _CALLGRAPH_PY)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
CallGraph = _mod.CallGraph
get_call_graph = _mod.get_call_graph


class StubFunc:
    """Minimal stand-in for binaryninja.Function."""

    def __init__(self, start, name):
        self.start = start
        self.name = name
        self.callees = []
        self.callers = []
        self.symbol = None

    def __repr__(self):
        return f"<StubFunc {self.name}@{self.start:#x}>"


class StubBV:
    """Minimal stand-in for binaryninja.BinaryView."""

    def __init__(self, funcs):
        self._by_name = {f.name: f for f in funcs}
        self._by_addr = {f.start: f for f in funcs}
        self.arch = None

    def get_functions_by_name(self, name):
        f = self._by_name.get(name)
        return [f] if f else []

    def get_function_at(self, addr):
        return self._by_addr.get(addr)


def _link(caller, callee):
    caller.callees.append(callee)
    callee.callers.append(caller)


def build_world():
    """Recreate test/src/call_graph.cpp as a stub graph."""
    leaf = StubFunc(0x1000, "leaf_add")

    chain_c = StubFunc(0x2000, "chain_c")
    chain_b = StubFunc(0x2010, "chain_b")
    chain_a = StubFunc(0x2020, "chain_a")

    d_bottom = StubFunc(0x3000, "diamond_bottom")
    d_left = StubFunc(0x3010, "diamond_left")
    d_right = StubFunc(0x3020, "diamond_right")
    d_top = StubFunc(0x3030, "diamond_top")

    factorial = StubFunc(0x4000, "factorial")
    ping = StubFunc(0x5000, "ping")
    pong = StubFunc(0x5010, "pong")

    run_all = StubFunc(0x6000, "run_all")
    main = StubFunc(0x7000, "main")

    # chain: chain_a -> chain_b -> chain_c -> leaf_add
    _link(chain_a, chain_b)
    _link(chain_b, chain_c)
    _link(chain_c, leaf)

    # diamond: top -> {left, right} -> bottom -> leaf_add
    _link(d_top, d_left)
    _link(d_top, d_right)
    _link(d_left, d_bottom)
    _link(d_right, d_bottom)
    _link(d_bottom, leaf)

    # self recursion + mutual recursion cycle
    _link(factorial, factorial)
    _link(ping, pong)
    _link(pong, ping)

    # entry
    for callee in (chain_a, d_top, factorial, ping, leaf):
        _link(run_all, callee)
    _link(main, run_all)

    funcs = [
        leaf, chain_c, chain_b, chain_a,
        d_bottom, d_left, d_right, d_top,
        factorial, ping, pong, run_all, main,
    ]
    return StubBV(funcs), {f.name: f for f in funcs}


def names(funcs):
    return sorted(f.name for f in funcs if f is not None)


def main():
    bv, f = build_world()
    cg = get_call_graph(bv)
    assert isinstance(cg, CallGraph)

    cg.expand(f["main"], direction="both", max_depth=12)

    # --- Queries ---
    assert "run_all" in names(cg.callees("main")), cg.callees("main")
    assert set(names(cg.callees("run_all"))) >= {
        "chain_a", "diamond_top", "factorial", "ping", "leaf_add"
    }, cg.callees("run_all")
    assert names(cg.callers("leaf_add")) == [
        "chain_c", "diamond_bottom", "run_all"
    ], cg.callers("leaf_add")

    # --- Node resolution by Function / int / name ---
    assert cg.has_node(f["ping"])
    assert cg.has_node(0x5000)
    assert cg.has_node("pong")

    # --- Search ---
    assert names(cg.search("diamond")) == [
        "diamond_bottom", "diamond_left", "diamond_right", "diamond_top"
    ]
    assert names(cg.search(r"^chain_[ab]$", regex=True)) == ["chain_a", "chain_b"]
    assert cg.find("factorial").start == 0x4000

    # --- Path finding: linear chain ---
    assert cg.reaches("chain_a", "leaf_add") is True
    assert cg.reaches("leaf_add", "chain_a") is False
    sp = cg.shortest_path("chain_a", "leaf_add")
    assert names(sp) and sp[0].name == "chain_a" and sp[-1].name == "leaf_add"
    assert len(sp) == 4, [x.name for x in sp]  # chain_a,b,c,leaf_add

    # --- Path finding: diamond has exactly two simple paths top->bottom ---
    paths = list(cg.all_paths("diamond_top", "diamond_bottom"))
    assert len(paths) == 2, [[x.name for x in p] for p in paths]

    # --- Cycle safety: mutual + self recursion ---
    assert "pong" in names(cg.callees("ping"))
    assert "ping" in names(cg.callees("pong"))
    assert cg.reaches("ping", "pong") and cg.reaches("pong", "ping")
    assert "factorial" in names(cg.callees("factorial"))  # self-edge

    # --- Traversal ---
    bfs = names(cg.bfs("run_all", direction="callees"))
    assert "leaf_add" in bfs and "run_all" in bfs, bfs
    dfs = names(cg.dfs("run_all", direction="callees"))
    assert set(dfs) == set(bfs), (dfs, bfs)
    # callers direction from leaf reaches the entry points
    up = names(cg.bfs("leaf_add", direction="callers"))
    assert "main" in up and "diamond_top" in up, up

    # --- Export ---
    sub = cg.subgraph("run_all", direction="callees")
    assert sub.number_of_nodes() >= 6
    d = cg.to_dict()
    assert {n["name"] for n in d["nodes"]} >= {"main", "run_all", "leaf_add"}
    assert all("caller" in e and "callee" in e for e in d["edges"])
    assert len(cg.to_edge_list()) == cg.to_networkx().number_of_edges()

    # --- Caching ---
    assert get_call_graph(bv) is cg
    assert get_call_graph(bv, refresh=True) is not cg

    print("OK: standalone CallGraph smoke passed")
    print("  graph:", repr(cg))
    print("  shortest chain_a->leaf_add:", [x.name for x in sp])
    print("  diamond simple paths:", len(paths))
    return 0


if __name__ == "__main__":
    sys.exit(main())
