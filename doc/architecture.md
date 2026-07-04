# Calltree — Architecture & Design

This document describes the design of the **Calltree** Binary Ninja plugin: an
alternative call-graph view that renders the incoming (callers) and outgoing
(callees) call trees for the current function, plus a headless Python API for
programmatic call-graph analysis.

- **Audience:** contributors and API users.
- **Scope:** every module, the data model, the threading model, and the control
  flow of each major operation (navigation, lazy expansion, expand-all, search,
  analysis refresh, pinning).

---

## 1. Overview

Calltree adds a sidebar to Binary Ninja with two trees for the current function:

- **Incoming Calls** — the callers of the function (and their callers, …).
- **Outgoing Calls** — the callees of the function (and their callees, …).

Both trees are views over a shared, lazily-grown call graph. The same graph is
exposed as a headless Python API (`CallGraph`) so it can be scripted from the
Binary Ninja console.

Design goals, in priority order:

1. **Never hang the UI**, even for very deep/dense call graphs.
2. **Stay responsive** — heavy work runs on background threads; the UI thread only
   touches Qt.
3. **Stay correct** as analysis evolves — invalidate only what changed.
4. **Be scriptable** — the graph core is UI-free and importable headlessly.

---

## 2. Module map

```
calltree/
├── __init__.py     Package entry. Exposes the headless API; loads the UI only
│                   when Binary Ninja's UI is enabled.
├── callgraph.py    UI-free call-graph core: `CallGraph` (networkx-backed),
│                   per-BinaryView cache, dirty tracking, worker-safe `gather_subtree`.
├── calltree.py     Qt widgets: the per-tab layout, the two call trees, lazy
│                   loading, search, expand-all, and click/navigation behavior.
├── init.py         The sidebar widget: tabs (Current + pinned), view/analysis
│                   callbacks, dirty-tracking notification, settings registration.
├── demangle.py     `demangle_name(bv, name)` — MS / GNUv3 demangling helper.
├── plugin.json     Plugin metadata (version, min BN version, license).
├── requirements.txt`networkx` dependency.
└── test/           Standalone tests (CMake C++ mirror + Python examples/smoke).
```

### Layering

```
        ┌──────────────────────────────────────────────┐
        │  Binary Ninja UI (Sidebar, ViewFrame, Qt)     │
        └───────────────┬──────────────────────────────┘
                        │ callbacks (notifyView*, analysis events, notifications)
        ┌───────────────▼──────────────────────────────┐
        │  init.py — CalltreeSidebarWidget              │
        │   • Current tab + pinned tabs (QTabWidget)    │
        │   • view/location/analysis callbacks          │
        │   • BinaryDataNotification (dirty tracking)    │
        └───────────────┬──────────────────────────────┘
                        │ owns / drives
        ┌───────────────▼──────────────────────────────┐
        │  calltree.py — CalltreeWidget / CallTreeLayout│
        │   • QTreeView + QStandardItemModel + proxy    │
        │   • lazy loading, search, expand-all, clicks  │
        └───────────────┬──────────────────────────────┘
                        │ reads / grows
        ┌───────────────▼──────────────────────────────┐
        │  callgraph.py — CallGraph (networkx.DiGraph)  │
        │   • lazy expand + memo, per-BV cache          │
        │   • dirty tracking, query/search/path API     │
        └───────────────────────────────────────────────┘
```

`__init__.py` exposes `CallGraph` and `get_call_graph` **without** importing the
UI, so `from calltree import get_call_graph` works headlessly. `init` (the UI) is
imported only under `binaryninja.core_ui_enabled()`.

---

## 3. Data model — `CallGraph` (callgraph.py)

`CallGraph` wraps a `networkx.DiGraph`:

- **Node** = a function **start address** (`int`) — stable and unique.
- **Edge** = **caller → callee**. Therefore:
  - `graph.successors(addr)` = **callees**,
  - `graph.predecessors(addr)` = **callers**.
- **Node attributes:** `name` (raw), `demangled`, `symbol_type`, `func` (the live
  `binaryninja.Function`).

Nodes accept a `Function`, an `int` address, or a `str` name anywhere a "node"
argument is expected (`_resolve_addr`).

### Lazy expansion + memoization

`expand(func, direction="both", max_depth=5, max_nodes=None)` grows the graph
around a root:

- BFS with a `visited` set → **bounded by unique functions** (linear in the
  reachable subgraph, *not* exponential).
- **Memoized** per `(root_addr, direction)` → the max depth already expanded, so
  repeated navigation is cheap.
- `apply_dirty()` runs first (see §6) so stale functions are rebuilt before use.
- `max_nodes` is an optional safety cap for bulk/whole-graph builds.

> Key distinction: the **graph** is linear in unique functions; the exponential
> blow-up only exists when unrolling the graph into a **tree** (a function on N
> paths appears N times). This is why the UI, not the graph, needs node budgets.

### Per-BinaryView cache

```python
_CACHE = weakref.WeakKeyDictionary()          # bv -> CallGraph
get_call_graph(bv, refresh=False)             # create/cached (main-thread use)
peek_call_graph(bv)                           # cached-or-None, never creates
```

`peek_call_graph` never allocates and only does a dict lookup, so it is safe to
call from worker threads (used by the dirty-tracking notification).

### Public API (headless-friendly)

| Category   | Methods |
|------------|---------|
| Grow       | `expand`, `build_all`, `ingest_subtree` |
| Query      | `callees`, `callers`, `neighbors`, `has_node`, `nodes`, `functions`, `display_name` |
| Search     | `search` (substring/regex, demangled/raw), `find` |
| Paths      | `reaches`, `shortest_path`, `all_paths` |
| Traversal  | `bfs`, `dfs`, `subgraph` |
| Export     | `to_networkx`, `to_dict`, `to_edge_list` |
| Lifecycle  | `clear`, `mark_dirty`, `apply_dirty`, `is_expanded` |

Example (Binary Ninja console):

```python
from calltree import get_call_graph
cg = get_call_graph(bv)
cg.expand(bv.get_functions_by_name("main")[0], direction="callees", max_depth=6)
cg.search("alloc")
cg.reaches("main", "malloc")
cg.shortest_path("main", "malloc")
```

---

## 4. UI structure (calltree.py + init.py)

```
CalltreeSidebarWidget (init.py)                 ← Binary Ninja SidebarWidget
├── toolbar: [pin] [remove]
└── QTabWidget
    ├── "Current"  → CalltreeWidget             ← tracks the active function
    └── "<pinned>" → CalltreeWidget (snapshots) ← frozen at pin time

CalltreeWidget (calltree.py)                    ← one tab
├── CurrentFunctionNameLayout   (the function header)
├── CallTreeLayout  is_caller=True   ("Incoming Calls")
└── CallTreeLayout  is_caller=False  ("Outgoing Calls")

CallTreeLayout (calltree.py)                    ← one tree
├── QTreeView ── QSortFilterProxyModel ── QStandardItemModel
└── CallTreeUtilLayout: [search box] [🔍] [+] [-] [depth spinbox]
```

- **`BNFuncItem`** is the tree row: it holds `func`, `level` (1-based depth),
  `loaded` (children populated?) and `expandable` (may have children?).
- **`CallTreeUtilLayout`** wires the toolbar controls to `CallTreeLayout`.

---

## 5. Threading model (the central invariant)

Heavy work (walking Binary Ninja's call sites, demangling thousands of names) must
not block the UI. The rules:

1. **Binary Ninja reads** (`func.callees`, `func.callers`, `demangle_name`) may run
   on **any thread** — BN reads are safe, and these functions don't mutate shared
   state.
2. **networkx and Qt are mutated on the MAIN thread ONLY.** Never touch the graph
   or the item model from a worker.
3. **Cross-thread hand-off** uses:
   - a thread-safe **dirty set** (`CallGraph.mark_dirty` under a lock), and
   - `binaryninja.execute_on_main_thread(...)` to marshal results back.

Helpers:

- **`_FnTask(BackgroundTaskThread)`** / **`_run_in_background(title, fn)`** — run a
  plain callable on a BN worker thread (shows a status-bar task).
- **`_collect_tree_rows(bv, root, is_caller, budget, needle=None)`** — the
  worker-side workhorse. It walks the whole subtree (BN reads only via
  `gather_subtree`), demangles + matches names, prunes, and returns **plain data**:
  a pre-order list of `(func, name, is_match, level)`. It touches **no** networkx
  and **no** Qt, so it is safe off-thread. The main thread turns these rows into
  `BNFuncItem`s.

This split — *gather plain data on a worker, build Qt on the main thread* — is what
keeps search and expand-all responsive.

---

## 6. Freshness — dirty tracking & analysis refresh

Analysis is not complete when a file first opens, and it changes as the user edits.
Calltree keeps the graph fresh **granularly** rather than wiping it:

- **`_CalltreeFunctionNotification`** (init.py) is a `BinaryDataNotification`
  registered per BinaryView (`NotificationType.FunctionUpdates`). Its
  `function_updated/added/removed` callbacks (which may run on analysis worker
  threads) call `peek_call_graph(bv).mark_dirty(func.start)` — a lock-guarded set
  insert only. **No graph mutation off-thread.**
- **`CallGraph.apply_dirty()`** runs on the main thread (at the top of `expand`, and
  after analysis completes). For each dirty address it removes the node (dropping
  its now-stale edges) and clears the expansion memo for it **and its former
  neighbors**, so correct edges are re-read on next expansion.
- **Analysis completion**: `notifyViewChanged` arms
  `bv.add_analysis_completion_event`. On completion, `_refresh_after_analysis`
  marks the current function dirty, calls `apply_dirty()`, re-renders the Current
  tab, and **re-arms** the event (BN completion events are one-shot). Marking the
  current function guarantees the first-open "callees discovered late" case is
  handled even if no explicit `function_updated` fired for it.

---

## 7. Lazy tree rendering (the anti-hang design)

Rendering every path of a deep graph is exponential. Instead, `CallTreeLayout`
loads on demand.

### Building a level

`_add_children(graph, parent_item, parent_func, parent_level, path)`:

1. `graph.expand(parent_func, direction, max_depth=1)` — pull just this node's
   direct neighbors.
2. Create a `BNFuncItem` per neighbor (capped at `MAX_CHILDREN_PER_NODE`; the
   overflow becomes a non-expandable "… N more" row).
3. A child gets an **expand placeholder** (a dummy child → the disclosure arrow) iff
   it *can* have visible children: `child_level < func_depth + 1`, it is not already
   on the root→node path (**cycle guard**), and `_has_neighbors` is true.

`_has_neighbors(graph, func)` prefers the graph when the node is already expanded
(avoids a BN read), else falls back to `func.callees/callers`.

### Expanding on demand

- The tree connects `QTreeView.expanded → _on_item_expanded → _ensure_children`.
- `_ensure_children(item)` (idempotent via `item.loaded`, gated by
  `item.expandable`) drops the placeholder and calls `_add_children` for the real
  children.
- The cycle path is recomputed by walking parent items (`_path_for`).

### Auto-reveal on navigation

`_auto_reveal(budget)` makes navigation *look* expanded without exploding:

1. **Load** breadth-first until `budget` nodes exist (`budget` = the
   `calltree.max_nodes` setting; the tree structure itself stops at `func_depth`).
2. **Then** `_expand_loaded_rows()` expands the loaded rows.

Loading and expanding are **separate passes** on purpose: expanding only after the
model has stopped changing prevents later inserts from resetting earlier
expansions. Rows that still hold a placeholder (unloaded, beyond the budget) stay
collapsed, so no blank placeholder rows are ever shown.

### Micro-optimizations

- The two theme brushes (`CodeSymbolColor`, `ImportColor`) are computed once per
  render, not per row.
- Row text reuses `CallGraph.display_name` (the demangled name cached on the node),
  which also guarantees a non-empty label (falls back to `sub_<addr>`).

---

## 8. Search — pruned call tree (calltree.py)

Search is **explicit** (Enter in the box or the 🔍 button), not per-keystroke, and
it covers the **entire** subtree regardless of depth or node caps.

Flow:

1. `do_search(text)` shows "Searching all calls…", then `_run_in_background` calls
   `_collect_tree_rows(bv, target, is_caller, SEARCH_TREE_NODES, needle=text)` on a
   worker.
2. The worker walks the whole subtree (`gather_subtree`, no cap), demangles every
   name, finds matches, computes **keep = matches ∪ all ancestors that can reach a
   match** (reverse BFS), and prunes the tree to those nodes — returning a pre-order
   `(func, name, is_match, level)` list.
3. On the main thread, `_on_search_tree` rebuilds the pruned tree (matches in
   **bold**) using a parent-stack reconstruction from the flat rows, then
   `expandAll()`.

Notes:

- Branches that don't lead to a match are **pruned away**; matches are shown in
  their call-path context (not a flat list).
- The worker DFS and the main-thread reconstruction are **iterative** (no Python
  recursion-limit issues on deep chains); cycles are shown once and not recursed.
- A `_search_token` invalidates stale/superseded searches; navigation and the `+`
  button exit search mode.
- `SEARCH_TREE_NODES` is only a **render** safety cap — the search *walk* itself is
  unbounded.

---

## 9. Expand-all (`+`) and collapse (`-`)

- **`+` / `expand_all`** shows the **entire reachable subtree**, ignoring the depth
  setting and the auto-expand cap (bounded only by `EXPAND_ALL_NODES`). It reuses
  `_collect_tree_rows(..., needle=None)` (keep = everything) on a background thread,
  then `_on_full_tree` builds the eager tree on the main thread. It exits search
  mode and is discarded if the user navigates away meanwhile (`_expanding` guards
  against overlap).
- **`-` / `collapse_all`** = `treeview.collapseAll()` (view-only).

This makes `+` distinct from navigation: navigation is depth-limited, `+` is
"show everything".

---

## 10. Navigation & click semantics

Two-level click model, consistent across the trees and the function header:

- **Single click = preview.** Navigate the *main disassembly view* without
  re-rooting the Current tab.
- **Double click = commit.** Navigate *and* re-root the Current tab onto the target.

Mechanism (`skip_next_update`, centralized on the sidebar):

- Tree single click → `goto_first_func_use` finds the **call site** (`ref.address`)
  and sets `skip_next_update = True` before navigating.
- Tree double click → `goto_func` navigates to the **function start** with
  `skip_next_update = False`.
- The function header (`CurrentFunctionNameLayout`) mirrors this: `preview_func`
  (single) vs `goto_func` (double). Because single and double click target the same
  address there, the header only arms `skip_next_update` when the navigation will
  actually move (checked via `prev_location`), and the double-click re-roots
  **explicitly** via `sidebar.set_current_function` rather than relying on a
  location event.

In `notifyViewLocationChanged` the sidebar checks `skip_next_update` **first**: if
set, it consumes the flag and returns without touching `self.cur_func` or the
Current tab (a pure preview). Otherwise it re-roots the Current tab onto the new
function. `prev_location` de-dupes "same address, different InstrIndex" events.

---

## 11. Tabs & pinning (init.py)

- The sidebar hosts a `QTabWidget`: index 0 is the **Current** tab (tracks the
  active function); other tabs are **pinned snapshots**.
- **Pin** (`pin_current_tab`) builds a new `CalltreeWidget`, force-renders it for
  the current function (bypassing the visibility guard), and adds it as a tab.
- Pinned tabs are **snapshots** — they behave like the Current tab for clicks
  (single = preview, double = commit) but are not rebuilt on navigation.
- Because a hidden tab's trees are not rebuilt while hidden (visibility guard in
  `update_widget`), the Current tab is refreshed when it becomes visible again:
  `QTabWidget.currentChanged → _on_tab_changed`, and the sidebar's `showEvent`, both
  call `_refresh_current_tab`.

---

## 12. Settings (init.py)

Registered under the `calltree` group:

| Setting                 | Default | Meaning |
|-------------------------|---------|---------|
| `calltree.in_depth`     | 5       | Initial incoming (callers) depth. |
| `calltree.out_depth`    | 5       | Initial outgoing (callees) depth. |
| `calltree.pin_name_len` | 10      | Max characters shown on a pinned tab label. |
| `calltree.max_nodes`    | 3000    | Safety cap on rows auto-expanded (BFS) on navigation. `minValue` 10, `maxValue` 1,000,000. Read dynamically each navigation. |

Code-level caps (module constants in calltree.py, promotable to settings):

| Constant                | Default | Meaning |
|-------------------------|---------|---------|
| `MAX_CHILDREN_PER_NODE` | 500     | Children rendered under one node before a "… N more" row. |
| `AUTO_EXPAND_NODES`     | 3000    | Fallback for the auto-expand cap if the setting is unset. |
| `EXPAND_ALL_NODES`      | 5000    | Node cap for the `+` full-tree build. |
| `SEARCH_TREE_NODES`     | 20000   | Render cap for the pruned search tree (the search walk is uncapped). |

---

## 13. Key control flows (sequences)

**Navigate to a function (Current tab visible):**
```
ViewFrame → notifyViewLocationChanged
  skip_next_update? ── yes → consume, return (preview; Current tab untouched)
                    └─ no  → set cur_func → set_current_function
                              → update_widget (each tree):
                                 clear → expand(cur_func, depth=1)
                                 → _add_children (root level, placeholders)
                                 → _auto_reveal(max_nodes):  load BFS → expand loaded
```

**Expand a row (user clicks the arrow):**
```
QTreeView.expanded → _on_item_expanded → _ensure_children
  → expand(node, depth=1) → _add_children(node) → (placeholders on grandchildren)
```

**Search (Enter / 🔍):**
```
do_search → show "Searching…" → _run_in_background:
  [worker] _collect_tree_rows(needle): gather_subtree(all) → demangle → match
           → keep = matches + ancestors → prune → rows
  → execute_on_main_thread → _on_search_tree: rebuild pruned tree (bold matches) → expandAll
```

**Expand-all (`+`):**
```
expand_all → exit search → _run_in_background:
  [worker] _collect_tree_rows(needle=None): gather_subtree(all) → demangle → rows (keep all)
  → execute_on_main_thread → _on_full_tree: build full tree (≤ EXPAND_ALL_NODES) → expandAll
```

**Analysis changes a function:**
```
[worker] BinaryDataNotification.function_updated → cg.mark_dirty(addr)   (set insert)
[main]   analysis completion → _refresh_after_analysis:
          mark current dirty → apply_dirty() (drop dirty nodes + neighbor memos)
          → re-render Current tab → re-arm completion event
```

---

## 14. Testing & validation

- **Headless graph logic** is fully testable without Binary Ninja/Qt. The core
  (`callgraph.py`) is UI-free and importable standalone (its demangle import falls
  back to identity). See `test/python/standalone_smoke.py` and
  `test/python/test_callgraph_api.py`, plus the CMake C++ mirror under `test/`.
- **UI code** (`calltree.py`, `init.py`) imports Binary Ninja / `binaryninjaui` /
  PySide6 and cannot run outside Binary Ninja. It is validated statically with
  `python3 -m py_compile` and `pyflakes`; behavior is verified manually in
  Binary Ninja.
- The only expected `pyflakes` note is `__init__.py: '.init' imported but unused` —
  that import is an intentional UI-load side effect.

---

## 15. Extension notes

- **Adding a graph query/analysis:** add a method to `CallGraph`; it is
  automatically available headlessly via `get_call_graph(bv)`.
- **Adding a heavy UI action:** do the walk in a `_collect_tree_rows`-style worker
  (BN reads → plain data), then build Qt on the main thread via
  `execute_on_main_thread`. Never touch networkx/Qt off-thread.
- **Changing caps:** the constants in §12 are safe to tune; `calltree.max_nodes` is
  already a live setting and a template for promoting the others.
- **Whole-program work (search/export over everything):** `CallGraph.build_all()`
  builds the full program graph; wrap it in a background task for the UI.
