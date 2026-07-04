"""Graph-backed call-graph data structure and Python API for the Calltree plugin.

This module is intentionally free of any UI (Qt / binaryninjaui) imports so that it
can be used headlessly from the Binary Ninja Python console, e.g.::

    from calltree import get_call_graph
    cg = get_call_graph(bv)
    cg.expand(bv.get_functions_by_name("main")[0], direction="callees", max_depth=6)
    cg.search("alloc")
    cg.reaches("main", "system")
    cg.shortest_path("main", "system")
    for func in cg.bfs("main", direction="callees", max_depth=3):
        print(func.name)

The graph is a ``networkx.DiGraph`` where each node is a function *start address*
(a stable, unique ``int``) and every edge points from a **caller** to a **callee**.
Therefore ``successors`` are callees and ``predecessors`` are callers.

Nodes are populated lazily around a root function (see :meth:`CallGraph.expand`)
and cached per :class:`~binaryninja.binaryview.BinaryView` via
:func:`get_call_graph`, which keeps the structure cheap even on large binaries.
"""

from __future__ import annotations

import re
import threading
import weakref

try:
    import networkx as nx
except ImportError as _nx_error:  # pragma: no cover - exercised only when missing
    nx = None
    _NX_ERROR = _nx_error
else:
    _NX_ERROR = None

try:
    from .demangle import demangle_name
except ImportError:  # allow standalone import (tests) outside the package context
    def demangle_name(bv, function_name):  # type: ignore[misc]
        return function_name


_NX_MESSAGE = (
    "calltree requires the 'networkx' package. Install it into Binary Ninja's "
    "Python environment via the 'Install python3 module' command palette action, "
    "or run 'pip install networkx' against Binary Ninja's interpreter."
)

# Surface a clear, one-time error in the Binary Ninja log if networkx is missing,
# without crashing plugin import (the UI degrades to empty trees).
if nx is None:  # pragma: no cover - depends on environment
    try:
        import binaryninja

        binaryninja.log_error(_NX_MESSAGE)
    except Exception:
        pass


def _require_networkx():
    if nx is None:
        raise ImportError(_NX_MESSAGE) from _NX_ERROR


def _safe_demangle(bv, name):
    try:
        return demangle_name(bv, name)
    except Exception:
        return name


def _dedup_by_addr(funcs):
    """Deduplicate function-like objects by start address (order-preserving)."""
    seen = {}
    for func in funcs:
        addr = getattr(func, "start", None)
        if addr is not None and addr not in seen:
            seen[addr] = func
    return list(seen.values())


def gather_subtree(root_func, is_caller, max_depth, max_nodes=None):
    """Walk a call subtree using only Binary Ninja reads (no networkx / Qt).

    Returns ``(edges, expanded)`` where ``edges`` is a list of ``(parent, child)``
    Function pairs (parent calls child for the callees direction; child calls parent
    for callers) and ``expanded`` is the set of start addresses whose neighbors were
    fully walked. ``max_nodes`` is an optional safety cap (``None`` = unlimited).
    Because it never touches shared state, this is safe to run on a Binary Ninja
    worker thread; feed the result to :meth:`CallGraph.ingest_subtree` on the main
    thread.
    """
    edges = []
    expanded = set()
    visited = {root_func.start}
    frontier = [(root_func, 0)]
    while frontier and (max_nodes is None or len(visited) < max_nodes):
        cur, depth = frontier.pop()
        if depth >= max_depth:
            continue
        try:
            neighbors = cur.callers if is_caller else cur.callees
        except Exception:
            neighbors = []
        seen = set()
        for nb in neighbors:
            if nb is None or nb.start in seen:
                continue
            seen.add(nb.start)
            edges.append((cur, nb))
            if nb.start not in visited:
                visited.add(nb.start)
                frontier.append((nb, depth + 1))
        expanded.add(cur.start)
    return edges, expanded


class CallGraph:
    """A lazily-expanded, cached call graph backed by :class:`networkx.DiGraph`.

    Edges point from caller to callee. All query methods accept a *node* argument
    that may be a Binary Ninja ``Function``, a function start address (``int``), or
    a function name (``str``).
    """

    def __init__(self, bv):
        _require_networkx()
        self.bv = bv
        self.graph = nx.DiGraph()
        # Memo of how deep a given (address, direction) root has been expanded.
        self._expanded = {}
        # Addresses flagged changed (thread-safe); applied on the main thread.
        self._dirty = set()
        self._dirty_lock = threading.Lock()

    # ------------------------------------------------------------------ #
    # Node / resolution helpers
    # ------------------------------------------------------------------ #
    def add_function(self, func):
        """Add ``func`` as a node (if new) and return its start address."""
        addr = func.start
        if not self.graph.has_node(addr):
            name = func.name
            self.graph.add_node(
                addr,
                name=name,
                demangled=_safe_demangle(self.bv, name),
                symbol_type=getattr(getattr(func, "symbol", None), "type", None),
                func=func,
            )
        return addr

    def _resolve_addr(self, node):
        """Return the start address for a Function / int / name, or ``None``."""
        if isinstance(node, bool):
            return None
        if isinstance(node, int):
            return node
        if isinstance(node, str):
            func = self.find(node)
            return func.start if func is not None else self._lookup_addr_by_name(node)
        return getattr(node, "start", None)

    def _lookup_addr_by_name(self, name):
        getter = getattr(self.bv, "get_functions_by_name", None)
        if getter is None:
            return None
        try:
            matches = getter(name)
        except Exception:
            return None
        return matches[0].start if matches else None

    def _func_for(self, addr):
        if self.graph.has_node(addr):
            return self.graph.nodes[addr].get("func")
        getter = getattr(self.bv, "get_function_at", None)
        if getter is not None:
            try:
                return getter(addr)
            except Exception:
                return None
        return None

    def _funcs_for(self, addrs):
        return [self._func_for(a) for a in addrs]

    @staticmethod
    def _neighbor_funcs(func, direction):
        if direction == "callers":
            return func.callers
        return func.callees

    # ------------------------------------------------------------------ #
    # Lazy expansion
    # ------------------------------------------------------------------ #
    def expand(self, func, direction="both", max_depth=5, max_nodes=None):
        """Expand the graph around ``func`` up to ``max_depth`` hops.

        ``direction`` is one of ``"callees"``, ``"callers"`` or ``"both"``.
        Expansion is memoized so repeated navigation is cheap, and cycles are
        handled via a visited set. ``max_nodes`` optionally caps total graph size
        (a safety valve for bulk/whole-graph builds). Returns ``self`` for chaining.
        """
        self.apply_dirty()
        if direction == "both":
            directions = ("callers", "callees")
        elif direction in ("callers", "callees"):
            directions = (direction,)
        else:
            raise ValueError("direction must be 'callers', 'callees' or 'both'")

        for one in directions:
            self._expand_one(func, one, max_depth, max_nodes)
        return self

    def _expand_one(self, func, direction, max_depth, max_nodes=None):
        root_addr = self.add_function(func)
        key = (root_addr, direction)
        if self._expanded.get(key, -1) >= max_depth:
            return
        self._expanded[key] = max_depth

        visited = {root_addr}
        frontier = [(func, 0)]
        while frontier:
            cur_func, depth = frontier.pop()
            if depth >= max_depth:
                continue
            for neighbor in _dedup_by_addr(self._neighbor_funcs(cur_func, direction)):
                nb_addr = self.add_function(neighbor)
                if direction == "callees":
                    self.graph.add_edge(cur_func.start, nb_addr)
                else:  # neighbor calls cur_func -> caller -> callee edge
                    self.graph.add_edge(nb_addr, cur_func.start)
                if nb_addr not in visited:
                    visited.add(nb_addr)
                    frontier.append((neighbor, depth + 1))
            if max_nodes is not None and self.graph.number_of_nodes() >= max_nodes:
                break

    # ------------------------------------------------------------------ #
    # Dirty tracking (granular invalidation)
    # ------------------------------------------------------------------ #
    def mark_dirty(self, node):
        """Flag a function (``Function`` or start address) as changed. Thread-safe.

        Only records the address; the graph is mutated later by :meth:`apply_dirty`
        on the main thread, so this is safe to call from analysis worker threads.
        """
        addr = node if isinstance(node, int) else getattr(node, "start", None)
        if addr is not None:
            with self._dirty_lock:
                self._dirty.add(addr)

    def apply_dirty(self):
        """Rebuild-on-next-use any functions flagged dirty (MAIN thread only).

        Removes each dirtied node (dropping its now-stale edges) and clears the
        expansion memo for it and its former neighbors, so the correct edges are
        re-read from analysis the next time those nodes are expanded.
        """
        with self._dirty_lock:
            if not self._dirty:
                return
            dirty = list(self._dirty)
            self._dirty.clear()
        for addr in dirty:
            if self.graph.has_node(addr):
                for succ in list(self.graph.successors(addr)):
                    self._expanded.pop((succ, "callers"), None)
                for pred in list(self.graph.predecessors(addr)):
                    self._expanded.pop((pred, "callees"), None)
                self.graph.remove_node(addr)
            self._expanded.pop((addr, "callees"), None)
            self._expanded.pop((addr, "callers"), None)

    def is_expanded(self, func, direction, min_depth=1):
        """True if ``func``'s ``direction`` neighbors are already in the graph.

        Lets callers avoid a Binary Ninja read when the answer is already known.
        """
        addr = getattr(func, "start", func if isinstance(func, int) else None)
        return addr is not None and self._expanded.get((addr, direction), -1) >= min_depth

    def ingest_subtree(self, edges, expanded, is_caller):
        """Merge gathered ``(parent, child)`` pairs into the graph (MAIN thread).

        Companion to :func:`gather_subtree`: the worker gathers the edges without
        touching networkx, and this adds them and marks the walked nodes expanded.
        """
        direction = "callers" if is_caller else "callees"
        for parent, child in edges:
            self.add_function(parent)
            self.add_function(child)
            if is_caller:  # child calls parent
                self.graph.add_edge(child.start, parent.start)
            else:
                self.graph.add_edge(parent.start, child.start)
        for addr in expanded:
            if self._expanded.get((addr, direction), -1) < 1:
                self._expanded[(addr, direction)] = 1

    def build_all(self, progress=None, is_cancelled=None):
        """Populate the graph with every function's direct call edges (whole program).

        Intended for bulk/whole-graph work (search, export). ``progress(done,
        total)`` and ``is_cancelled()`` are optional callbacks. This reads analysis
        and mutates networkx, so run it on the thread that owns the graph (or on a
        private CallGraph that is swapped in on the main thread).
        """
        self.apply_dirty()
        funcs = list(getattr(self.bv, "functions", None) or [])
        total = len(funcs)
        for i, func in enumerate(funcs):
            if is_cancelled is not None and is_cancelled():
                break
            self.add_function(func)
            for callee in _dedup_by_addr(self._neighbor_funcs(func, "callees")):
                self.add_function(callee)
                self.graph.add_edge(func.start, callee.start)
            self._expanded[(func.start, "callees")] = 1
            if progress is not None:
                progress(i + 1, total)
        # The whole graph is present now, so every node's callers are known too.
        for addr in list(self.graph.nodes):
            self._expanded.setdefault((addr, "callers"), 1)
            self._expanded.setdefault((addr, "callees"), 1)
        return self

    # ------------------------------------------------------------------ #
    # Queries
    # ------------------------------------------------------------------ #
    def callees(self, node):
        """Functions called by ``node`` (graph successors)."""
        addr = self._resolve_addr(node)
        if addr is None or not self.graph.has_node(addr):
            return []
        return self._funcs_for(self.graph.successors(addr))

    def callers(self, node):
        """Functions that call ``node`` (graph predecessors)."""
        addr = self._resolve_addr(node)
        if addr is None or not self.graph.has_node(addr):
            return []
        return self._funcs_for(self.graph.predecessors(addr))

    def neighbors(self, node, direction="callees"):
        """Directional neighbors of ``node`` (``"callees"`` or ``"callers"``)."""
        if direction == "callers":
            return self.callers(node)
        return self.callees(node)

    def has_node(self, node):
        addr = self._resolve_addr(node)
        return addr is not None and self.graph.has_node(addr)

    def nodes(self):
        """All function start addresses currently in the graph."""
        return list(self.graph.nodes)

    def functions(self):
        """All ``Function`` objects currently in the graph."""
        return [data.get("func") for _, data in self.graph.nodes(data=True)]

    def display_name(self, func, demangled=True):
        """Return a non-empty (demangled) display name for ``func``.

        Reuses the name computed when the node was added so the UI does not
        re-demangle on every rendered row; falls back to demangling on the fly, and
        finally to ``sub_<addr>`` so a row is never blank (e.g. unnamed thunks).
        """
        addr = getattr(func, "start", func if isinstance(func, int) else None)
        name = ""
        if addr is not None and self.graph.has_node(addr):
            data = self.graph.nodes[addr]
            name = (data.get("demangled") if demangled else data.get("name")) or data.get(
                "name"
            ) or ""
        if not name:
            raw = getattr(func, "name", "") or ""
            name = (_safe_demangle(self.bv, raw) if demangled else raw) or raw
        if not name and isinstance(addr, int):
            name = f"sub_{addr:x}"
        return name or "(unnamed)"

    # ------------------------------------------------------------------ #
    # Search
    # ------------------------------------------------------------------ #
    def search(self, pattern, regex=False, demangled=True):
        """Return functions whose name matches ``pattern``.

        By default this is a case-insensitive substring match against the
        demangled name. Set ``regex=True`` for a regular-expression search, or
        ``demangled=False`` to match the raw (mangled) symbol name.
        """
        if regex:
            compiled = re.compile(pattern)

            def matches(name):
                return bool(compiled.search(name))
        else:
            needle = pattern.lower()

            def matches(name):
                return needle in name.lower()

        results = []
        for _, data in self.graph.nodes(data=True):
            name = data.get("demangled") if demangled else data.get("name")
            if not name:
                name = data.get("name") or ""
            if matches(name):
                results.append(data.get("func"))
        return results

    def find(self, name, demangled=True):
        """Return the first function whose (demangled or raw) name equals ``name``."""
        for _, data in self.graph.nodes(data=True):
            candidate = data.get("demangled") if demangled else data.get("name")
            if candidate == name or data.get("name") == name:
                return data.get("func")
        return None

    # ------------------------------------------------------------------ #
    # Path finding (networkx-powered)
    # ------------------------------------------------------------------ #
    def reaches(self, src, dst):
        """True if ``dst`` is reachable from ``src`` following call edges."""
        s, d = self._resolve_addr(src), self._resolve_addr(dst)
        if s is None or d is None:
            return False
        if not (self.graph.has_node(s) and self.graph.has_node(d)):
            return False
        return nx.has_path(self.graph, s, d)

    def shortest_path(self, src, dst):
        """Shortest call path from ``src`` to ``dst`` as a list of functions."""
        s, d = self._resolve_addr(src), self._resolve_addr(dst)
        if s is None or d is None:
            return []
        if not (self.graph.has_node(s) and self.graph.has_node(d)):
            return []
        try:
            path = nx.shortest_path(self.graph, s, d)
        except nx.NetworkXNoPath:
            return []
        return self._funcs_for(path)

    def all_paths(self, src, dst, cutoff=None):
        """Yield every simple call path from ``src`` to ``dst`` (lists of functions)."""
        s, d = self._resolve_addr(src), self._resolve_addr(dst)
        if s is None or d is None:
            return
        if not (self.graph.has_node(s) and self.graph.has_node(d)):
            return
        for path in nx.all_simple_paths(self.graph, s, d, cutoff=cutoff):
            yield self._funcs_for(path)

    # ------------------------------------------------------------------ #
    # Traversal / export
    # ------------------------------------------------------------------ #
    def _directed_view(self, direction):
        if direction == "callers":
            return self.graph.reverse(copy=False)
        return self.graph

    def bfs(self, root, direction="callees", max_depth=None):
        """Breadth-first traversal from ``root`` (root included as first element)."""
        addr = self._resolve_addr(root)
        if addr is None or not self.graph.has_node(addr):
            return []
        view = self._directed_view(direction)
        order = [addr]
        order.extend(v for _, v in nx.bfs_edges(view, addr, depth_limit=max_depth))
        return self._funcs_for(order)

    def dfs(self, root, direction="callees", max_depth=None):
        """Depth-first traversal from ``root`` (root included as first element)."""
        addr = self._resolve_addr(root)
        if addr is None or not self.graph.has_node(addr):
            return []
        view = self._directed_view(direction)
        order = [addr]
        order.extend(v for _, v in nx.dfs_edges(view, addr, depth_limit=max_depth))
        return self._funcs_for(order)

    def subgraph(self, root, direction="callees", max_depth=None):
        """Return a ``networkx.DiGraph`` of everything reachable from ``root``.

        Edge directions in the result are preserved as caller->callee regardless
        of the traversal ``direction``.
        """
        addr = self._resolve_addr(root)
        if addr is None or not self.graph.has_node(addr):
            return nx.DiGraph()
        view = self._directed_view(direction)
        keep = {addr}
        for u, v in nx.bfs_edges(view, addr, depth_limit=max_depth):
            keep.add(u)
            keep.add(v)
        return self.graph.subgraph(keep).copy()

    def to_networkx(self):
        """Return the underlying ``networkx.DiGraph`` (live, not a copy)."""
        return self.graph

    def to_dict(self):
        """Serializable dict of nodes/edges (addresses + names only)."""
        return {
            "nodes": [
                {
                    "address": addr,
                    "name": data.get("name"),
                    "demangled": data.get("demangled"),
                }
                for addr, data in self.graph.nodes(data=True)
            ],
            "edges": [{"caller": u, "callee": v} for u, v in self.graph.edges],
        }

    def to_edge_list(self):
        """Return call edges as a list of ``(caller_addr, callee_addr)`` tuples."""
        return list(self.graph.edges)

    def clear(self):
        """Drop all nodes/edges, the expansion memo and pending dirty flags."""
        self.graph.clear()
        self._expanded.clear()
        with self._dirty_lock:
            self._dirty.clear()

    # ------------------------------------------------------------------ #
    # Dunder conveniences
    # ------------------------------------------------------------------ #
    def __len__(self):
        return self.graph.number_of_nodes()

    def __contains__(self, node):
        return self.has_node(node)

    def __repr__(self):
        return (
            f"<CallGraph nodes={self.graph.number_of_nodes()} "
            f"edges={self.graph.number_of_edges()}>"
        )


# Per-BinaryView cache so the graph is shared/grown across navigations.
_CACHE = weakref.WeakKeyDictionary()


def get_call_graph(bv, refresh=False):
    """Return the cached :class:`CallGraph` for ``bv``, creating it if needed.

    Pass ``refresh=True`` to discard any cached graph and start fresh (useful
    after analysis has changed).
    """
    _require_networkx()
    if not refresh:
        existing = _CACHE.get(bv)
        if existing is not None:
            return existing
    call_graph = CallGraph(bv)
    try:
        _CACHE[bv] = call_graph
    except TypeError:
        # bv is not weak-referenceable (e.g. a stub); skip caching.
        pass
    return call_graph


def peek_call_graph(bv):
    """Return the cached CallGraph for ``bv`` if one exists, else ``None``.

    Unlike :func:`get_call_graph` this never creates a graph, so it is safe to call
    from non-main threads (e.g. analysis notifications) purely to flag dirty
    functions via :meth:`CallGraph.mark_dirty`.
    """
    return _CACHE.get(bv)
