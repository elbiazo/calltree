from PySide6.QtCore import QSortFilterProxyModel
from PySide6.QtGui import (
    QStandardItemModel,
    QStandardItem,
    QBrush,
    QIcon,
    QPixmap,
    QPainter,
    QPen,
    QColor,
    QPalette,
)
from PySide6.QtCore import QSize, Qt
from PySide6.QtWidgets import QTreeView
from PySide6.QtWidgets import (
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QLineEdit,
    QSpinBox,
    QTextEdit,
    QWidget,
    QHeaderView,
    QAbstractItemView,
)
from binaryninja.settings import Settings

from binaryninja import (
    Function,
    ThemeColor,
    BackgroundTaskThread,
    execute_on_main_thread,
)
from binaryninja.enums import SymbolType
from binaryninjaui import getThemeColor


from .callgraph import get_call_graph, gather_subtree
from .demangle import demangle_name


# Lazy-loading safety caps. Rendering the whole call tree eagerly is exponential in
# dense graphs, so children load on demand and reveals are budgeted. Kept as module
# constants for now (easy to promote to Settings later).
MAX_CHILDREN_PER_NODE = 500  # children shown under one node before a "… N more" row
AUTO_EXPAND_NODES = 3000  # safety cap on rows auto-expanded (to func_depth) on navigation
EXPAND_ALL_NODES = 5000  # rows revealed by the expand-all (+) button
SEARCH_TREE_NODES = 20000  # render safety cap on the pruned search-result call tree


def _search_icon(color: QColor, size: int = 16) -> QIcon:
    """Draw a small magnifying-glass icon for the search button."""
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing, True)
    painter.setPen(QPen(color, 2))
    painter.setBrush(Qt.NoBrush)
    painter.drawEllipse(2, 2, 8, 8)  # lens
    painter.drawLine(9, 9, 14, 14)  # handle
    painter.end()
    return QIcon(pixmap)


def _pm_icon(color: QColor, plus: bool, size: int = 16) -> QIcon:
    """Draw a plus-in-a-box (expand) or minus-in-a-box (collapse) icon."""
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing, True)
    painter.setPen(QPen(color, 1.5))
    painter.setBrush(Qt.NoBrush)
    painter.drawRoundedRect(3, 3, 10, 10, 2, 2)
    painter.drawLine(6, 8, 10, 8)  # horizontal bar (minus / part of plus)
    if plus:
        painter.drawLine(8, 6, 8, 10)  # vertical bar completes the plus
    painter.end()
    return QIcon(pixmap)


class _FnTask(BackgroundTaskThread):
    """Run a plain callable on a Binary Ninja worker thread (keeps the UI free
    during the compute-heavy call-graph walk)."""

    def __init__(self, title, fn):
        super().__init__(title, can_cancel=False)
        self._fn = fn

    def run(self):
        try:
            self._fn()
        except Exception:
            pass


def _run_in_background(title, fn):
    _FnTask(title, fn).start()


def _collect_tree_rows(bv, root_func, is_caller, budget, needle=None):
    """Walk the whole subtree (BN reads only) and return pre-order rows
    ``(func, name, is_match, level)`` for a tree bounded by ``budget``.

    With ``needle`` the tree is pruned to the paths leading to name matches
    (``is_match`` marks them) and ``found`` is False when nothing matches. With
    ``needle=None`` the full reachable tree is returned (``found`` always True).
    Touches only Binary Ninja reads, so it is safe to run off the main thread.
    """
    try:
        edges, _ = gather_subtree(root_func, is_caller, 10 ** 9, None)
    except Exception:
        edges = []

    funcs = {root_func.start: root_func}
    adj = {}
    radj = {}
    for parent, child in edges:
        funcs.setdefault(parent.start, parent)
        funcs.setdefault(child.start, child)
        adj.setdefault(parent.start, []).append(child)
        radj.setdefault(child.start, []).append(parent.start)

    names = {}
    for addr, fn in funcs.items():
        try:
            names[addr] = demangle_name(bv, fn.name) or fn.name or f"sub_{addr:x}"
        except Exception:
            names[addr] = getattr(fn, "name", "") or f"sub_{addr:x}"

    if needle is None:
        keep = None  # keep everything (full "expand all" tree)
        matches = set()
    else:
        matches = {addr for addr, name in names.items() if needle in name.lower()}
        if not matches:
            return [], False
        # keep = matches plus every ancestor that can reach one (reverse BFS).
        keep = set(matches)
        stack = list(matches)
        while stack:
            for parent_addr in radj.get(stack.pop(), ()):
                if parent_addr not in keep:
                    keep.add(parent_addr)
                    stack.append(parent_addr)

    # Iterative pre-order DFS over kept nodes (iterative to avoid deep recursion),
    # with a per-branch cycle guard.
    rows = []
    remaining = budget
    path_set = {root_func.start}
    dfs = [[iter(adj.get(root_func.start, ())), root_func.start]]
    while dfs and remaining > 0:
        it, node_addr = dfs[-1]
        child = None
        for candidate in it:
            if keep is None or candidate.start in keep:
                child = candidate
                break
        if child is None:
            dfs.pop()
            path_set.discard(node_addr)
            continue
        rows.append(
            (child, names.get(child.start, ""), child.start in matches, len(dfs))
        )
        remaining -= 1
        if child.start not in path_set:
            path_set.add(child.start)
            dfs.append([iter(adj.get(child.start, ())), child.start])
    return rows, True


class CalltreeWidget(QWidget):
    """One call-tree tab: the current-function label plus the incoming and
    outgoing call trees. ``sidebar`` owns this widget and is passed down so tree
    clicks can tell it whether to re-root the Current tab on navigation."""

    def __init__(self, sidebar=None):
        super().__init__()
        in_func_depth = Settings().get_integer("calltree.in_depth")
        out_func_depth = Settings().get_integer("calltree.out_depth")

        self.in_calltree = CallTreeLayout("Incoming Calls", in_func_depth, True, sidebar)
        self.out_calltree = CallTreeLayout("Outgoing Calls", out_func_depth, False, sidebar)
        self.cur_func_layout = CurrentFunctionNameLayout(sidebar)
        self.cur_func_text = self.cur_func_layout.cur_func_text

        calltree_layout = QVBoxLayout()
        calltree_layout.addLayout(self.cur_func_layout)
        calltree_layout.addLayout(self.in_calltree)
        calltree_layout.addLayout(self.out_calltree)
        calltree_layout.setSpacing(0)
        calltree_layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(calltree_layout)


class BNFuncItem(QStandardItem):
    """A tree row bound to a Binary Ninja ``Function``.

    Built via :meth:`CallTreeLayout._make_item` so the (cached) demangled name and
    theme brush are computed once by the caller rather than per item. ``level`` is
    the 1-based tree depth (top-level rows are level 1); ``loaded`` tracks whether
    the row's real children have been populated, and ``expandable`` whether it may
    have children at all (both drive lazy loading).
    """

    def __init__(self, func: Function, text: str, brush: QBrush, level: int):
        super().__init__()
        self.func = func
        self.level = level
        self.loaded = False
        self.expandable = False
        self.setText(text)
        self.setForeground(brush)
        self.setEditable(False)


class CurrentFunctionNameLayout(QHBoxLayout):
    """Header showing the pane's root function. Clicking mirrors the call trees: a
    single click previews (navigate the main view without re-rooting the Current
    tab), a double click commits (navigate and re-root the Current tab)."""

    def __init__(self, sidebar=None):
        super().__init__()
        self.sidebar = sidebar
        self.binary_view = None
        self.cur_func_text = QTextEdit()
        self.cur_func_text.setReadOnly(True)
        self.cur_func_text.setMaximumHeight(30)
        self.cur_func_text.setAlignment(Qt.AlignLeft | Qt.AlignTop)
        self.cur_func_text.setLineWrapMode(QTextEdit.NoWrap)
        self.cur_func_text.mousePressEvent = self.preview_func
        self.cur_func_text.mouseDoubleClickEvent = self.goto_func
        super().addWidget(self.cur_func_text)

    # TODO: really should check the address as well as name; matching on name alone can fail.
    def _lookup_func(self):
        if self.binary_view is None:
            return None
        funcs = self.binary_view.get_functions_by_name(self.cur_func_text.toPlainText())
        return funcs[0] if funcs else None

    def preview_func(self, event):
        """Single click: navigate the main view to the function without re-rooting
        the Current tab. skip_next_update is only armed when the navigation will
        actually move the view; otherwise the flag would dangle (no location change
        to consume it) and swallow the next real navigation."""
        func = self._lookup_func()
        if func is None:
            return
        if self.sidebar is not None:
            prev = self.sidebar.prev_location
            if prev is None or prev[0] != func.start:
                self.sidebar.skip_next_update = True
        self.binary_view.navigate(self.binary_view.view, func.start)

    def goto_func(self, event):
        """Double click: navigate the main view to the function and re-root the
        Current tab onto it. The re-root is done explicitly because single and
        double click target the same address, so the double click's navigate may be
        a no-op that fires no location change."""
        func = self._lookup_func()
        if func is None:
            return
        if self.sidebar is not None:
            self.sidebar.set_current_function(func)
            self.sidebar.skip_next_update = False
        self.binary_view.navigate(self.binary_view.view, func.start)


# Search bar plus expand/collapse and depth controls for one CallTreeLayout.
class CallTreeUtilLayout(QHBoxLayout):
    def __init__(self, calltree: "CallTreeLayout"):
        super().__init__()
        self.calltree = calltree
        btn_size = QSize(25, 25)
        icon_color = calltree.treeview.palette().color(QPalette.ButtonText)

        self.func_filter = QLineEdit()
        self.func_filter.setPlaceholderText("search all calls (Enter)")
        # Search is explicit (Enter or the button), not per-keystroke.
        self.func_filter.returnPressed.connect(self.trigger_search)

        self.search_button = QPushButton()
        self.search_button.setIcon(_search_icon(icon_color))
        self.search_button.setFixedSize(btn_size)
        self.search_button.setToolTip(
            "Search the entire call subtree by name (ignores depth / node caps)"
        )
        self.search_button.clicked.connect(self.trigger_search)

        self.expand_all_button = QPushButton()
        self.expand_all_button.setIcon(_pm_icon(icon_color, plus=True))
        self.expand_all_button.setToolTip("Expand the full call subtree")
        self.expand_all_button.setFixedSize(btn_size)
        self.expand_all_button.clicked.connect(self.calltree.expand_all)

        self.collapse_all_button = QPushButton()
        self.collapse_all_button.setIcon(_pm_icon(icon_color, plus=False))
        self.collapse_all_button.setToolTip("Collapse all")
        self.collapse_all_button.setFixedSize(btn_size)
        self.collapse_all_button.clicked.connect(self.calltree.collapse_all)

        self.spinbox = QSpinBox()
        self.spinbox.valueChanged.connect(self.spinbox_changed)
        self.spinbox.setValue(self.calltree.func_depth)

        super().addWidget(self.func_filter)
        super().addWidget(self.search_button)
        super().addWidget(self.expand_all_button)
        super().addWidget(self.collapse_all_button)
        super().addWidget(self.spinbox)

    def trigger_search(self):
        self.calltree.do_search(self.func_filter.text())

    def spinbox_changed(self):
        self.calltree.func_depth = self.spinbox.value()
        if self.calltree.cur_func is not None:
            self.calltree.update_widget(self.calltree.cur_func)


class CallTreeLayout(QVBoxLayout):
    # Set once if networkx is unavailable, to avoid spamming the log on navigation.
    _warned_missing_networkx = False

    def __init__(self, label_name: str, depth: int, is_caller: bool, sidebar=None):
        super().__init__()
        self.sidebar = sidebar
        self.label_name = label_name
        self.is_caller = is_caller
        self.func_depth = depth
        self.cur_func = None
        self.binary_view = None
        self._node_count = 0
        self._expanding = False
        self._search_active = False
        self._search_token = 0
        self._search_text = ""
        self._suppress_fit = False
        self._brush_func = None
        self._brush_import = None

        self.treeview = QTreeView()
        self.model = QStandardItemModel()
        self.proxy_model = QSortFilterProxyModel(self.treeview)
        self.proxy_model.setSourceModel(self.model)
        self.treeview.setModel(self.proxy_model)
        self.treeview.setExpandsOnDoubleClick(False)
        # Allow horizontal scrolling to the full width: an Interactive column that we
        # size explicitly (see _fit_column). ResizeToContents only measures up to
        # `resizeContentsPrecision` rows, so deep/wide rows past that were cut off;
        # a high precision + an explicit resize after each build measures them all.
        header = self.treeview.header()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setResizeContentsPrecision(50000)
        self.treeview.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.treeview.setTextElideMode(Qt.ElideNone)

        # Single click jumps to the call site; double click drills into the function.
        self.treeview.clicked.connect(self.goto_first_func_use)
        self.treeview.doubleClicked.connect(self.goto_func)
        # Lazily populate a row's children the first time it is expanded.
        self.treeview.expanded.connect(self._on_item_expanded)

        self.set_label(self.label_name)
        super().addWidget(self.treeview)
        self.util = CallTreeUtilLayout(self)
        super().addLayout(self.util)

    def do_search(self, text):
        """Search the *entire* call subtree (every callee/caller, ignoring the depth
        and node caps) for functions whose name matches ``text``, then show the
        pruned call tree of the paths leading to each match (matches in bold).

        Triggered explicitly (Enter or the search button), not per keystroke. The
        whole walk + name matching runs on a background thread; only the Qt tree is
        built on the main thread. An empty query restores the normal call tree."""
        text = text.strip()
        if not text:
            self._exit_search()
            return
        if self.cur_func is None or self.binary_view is None:
            return
        self._search_active = True
        self._search_text = text
        self._search_token += 1
        token = self._search_token
        target, is_caller, bv = self.cur_func, self.is_caller, self.binary_view
        needle = text.lower()
        self._show_info("Searching all calls…")

        def work():
            rows, found = _collect_tree_rows(
                bv, target, is_caller, SEARCH_TREE_NODES, needle
            )
            execute_on_main_thread(lambda: self._on_search_tree(token, rows, found))

        _run_in_background("Calltree: searching all calls", work)

    def _on_search_tree(self, token, rows, found):
        if token != self._search_token or not self._search_active:
            return  # a newer search / navigation superseded this one
        self._reset_model()
        root = self.model.invisibleRootItem()
        if not found:
            self._append_info(root, "No matches")
            return
        self._ensure_brushes()
        # Rebuild the pruned tree from the pre-order (func, name, is_match, level) rows.
        parents = {0: root}
        for func, name, is_match, level in rows:
            item = BNFuncItem(func, name, self._brush_for(func), level)
            self._node_count += 1
            if is_match:
                font = item.font()
                font.setBold(True)
                item.setFont(font)
            parents.get(level - 1, root).appendRow(item)
            parents[level] = item
        self._suppress_fit = True
        try:
            self.treeview.expandAll()
        finally:
            self._suppress_fit = False
        self._fit_column()

    def _show_info(self, text):
        self._reset_model()
        self._append_info(self.model.invisibleRootItem(), text)

    def _append_info(self, root, text):
        item = QStandardItem(text)
        item.setEditable(False)
        item.setSelectable(False)
        root.appendRow(item)

    def _reset_model(self):
        self.proxy_model.setFilterRegularExpression("")
        self.model.clear()
        self._node_count = 0
        self.set_label(self.label_name)

    def _exit_search(self):
        was_active = self._search_active
        self._search_active = False
        self._search_token += 1  # invalidate any in-flight search
        if was_active and self.cur_func is not None:
            self.update_widget(self.cur_func, force=True)

    def expand_all(self):
        """Show the entire reachable call subtree (ignoring the depth setting and the
        auto-expand cap), bounded by EXPAND_ALL_NODES. The heavy walk runs on a
        background thread; the tree is built on the main thread when it finishes."""
        if self._expanding or self.cur_func is None or self.binary_view is None:
            return
        self._search_active = False  # + overrides a shown search result
        self._search_token += 1
        self._expanding = True
        target, is_caller, bv = self.cur_func, self.is_caller, self.binary_view

        def work():
            rows, _ = _collect_tree_rows(bv, target, is_caller, EXPAND_ALL_NODES, None)
            execute_on_main_thread(lambda: self._on_full_tree(target, rows))

        _run_in_background("Calltree: expanding call tree", work)

    def _on_full_tree(self, target, rows):
        try:
            # Discard if the user navigated away or started a search meanwhile.
            if self.cur_func is not target or self._search_active:
                return
            self._reset_model()
            self._ensure_brushes()
            root = self.model.invisibleRootItem()
            parents = {0: root}
            for func, name, _is_match, level in rows:
                item = BNFuncItem(func, name, self._brush_for(func), level)
                self._node_count += 1
                parents.get(level - 1, root).appendRow(item)
                parents[level] = item
            self._suppress_fit = True
            try:
                self.treeview.expandAll()
            finally:
                self._suppress_fit = False
            self._fit_column()
        finally:
            self._expanding = False

    def collapse_all(self):
        self.treeview.collapseAll()
        self._fit_column()

    def goto_first_func_use(self, index):
        """Single click: navigate to where the parent calls this function, without
        re-rooting the Current tab."""
        source_index = self.proxy_model.mapToSource(index)
        item = self.model.itemFromIndex(source_index)
        func = getattr(item, "func", None)
        if func is None:  # a placeholder or "… N more" marker, not a function row
            return
        bv = self.binary_view
        if bv is None:
            return

        parent_item = self.model.itemFromIndex(source_index.parent())
        parent_func = getattr(parent_item, "func", None) or self.cur_func
        if parent_func is None:
            return

        if self.is_caller:
            caller, callee = func, parent_func
        else:
            caller, callee = parent_func, func

        for ref in caller.call_sites:
            if callee.start in bv.get_callees(ref.address, ref.function):
                break
        else:
            # callee not found among the caller's call sites
            return

        self._request_skip_update(True)
        self.binary_view.navigate(self.binary_view.view, ref.address)

    def goto_func(self, index):
        """Double click: navigate to the function start and let the Current tab
        re-root onto it."""
        item = self.model.itemFromIndex(self.proxy_model.mapToSource(index))
        func = getattr(item, "func", None)
        if func is None:
            return
        self._request_skip_update(False)
        self.binary_view.navigate(self.binary_view.view, func.start)

    def _request_skip_update(self, value: bool):
        # Tell the owning sidebar whether the next view-location change (caused by
        # the navigate() call below) should skip re-rendering the Current tab. This
        # works from any tab, including pinned snapshots.
        if self.sidebar is not None:
            self.sidebar.skip_next_update = value

    def _direction(self) -> str:
        """Graph traversal direction for this tree (incoming calls == callers)."""
        return "callers" if self.is_caller else "callees"

    def _call_graph(self):
        """Return the shared CallGraph for the current view, or None if unavailable."""
        bv = self.binary_view
        if bv is None:
            return None
        try:
            return get_call_graph(bv)
        except ImportError:
            if not CallTreeLayout._warned_missing_networkx:
                CallTreeLayout._warned_missing_networkx = True
                try:
                    import binaryninja

                    binaryninja.log_error(
                        "calltree: 'networkx' is not installed, call trees are "
                        "disabled. Install it via the 'Install python3 module' "
                        "command or 'pip install networkx'."
                    )
                except Exception:
                    pass
            return None

    # ------------------------------------------------------------------ #
    # Lazy tree building
    # ------------------------------------------------------------------ #
    def _ensure_brushes(self):
        if self._brush_func is None:
            self._brush_func = QBrush(getThemeColor(ThemeColor.CodeSymbolColor))
            self._brush_import = QBrush(getThemeColor(ThemeColor.ImportColor))

    def _brush_for(self, func):
        symbol = getattr(func, "symbol", None)
        is_func = getattr(symbol, "type", None) == SymbolType.FunctionSymbol
        return self._brush_func if is_func else self._brush_import

    def _make_item(self, graph, func, level):
        item = BNFuncItem(func, graph.display_name(func), self._brush_for(func), level)
        self._node_count += 1
        return item

    @staticmethod
    def _placeholder():
        # A dummy child so a row shows an expand arrow before its real children are
        # loaded (see _ensure_children / _on_item_expanded).
        item = QStandardItem()
        item.setEditable(False)
        return item

    @staticmethod
    def _more_marker(count):
        item = QStandardItem(f"… {count} more")
        item.setEditable(False)
        item.setSelectable(False)
        return item

    def _has_neighbors(self, graph, func):
        direction = self._direction()
        # Prefer the graph when this node's neighbors are already known, to avoid a
        # Binary Ninja read (notably after a background expand-all pre-fills them).
        if graph is not None and graph.is_expanded(func, direction):
            return any(n is not None for n in graph.neighbors(func, direction))
        try:
            neighbors = func.callers if self.is_caller else func.callees
        except Exception:
            return False
        return any(n is not None for n in neighbors)

    def _add_children(self, graph, parent_item, parent_func, parent_level, path):
        """Add ``parent_func``'s direct neighbors under ``parent_item`` (one level).

        A child that could be expanded further gets a placeholder child so its
        expand arrow appears; the real children load lazily on expand. Children are
        capped, with a trailing "… N more" marker when the cap is exceeded.
        """
        self._ensure_brushes()
        graph.expand(parent_func, direction=self._direction(), max_depth=1)
        neighbors = [
            n for n in graph.neighbors(parent_func, self._direction()) if n is not None
        ]
        child_level = parent_level + 1
        shown = neighbors[:MAX_CHILDREN_PER_NODE]
        for neighbor in shown:
            item = self._make_item(graph, neighbor, child_level)
            parent_item.appendRow(item)
            if (
                child_level < self.func_depth + 1
                and neighbor.start not in path
                and self._has_neighbors(graph, neighbor)
            ):
                item.appendRow(self._placeholder())
                item.expandable = True
        extra = len(neighbors) - len(shown)
        if extra > 0:
            parent_item.appendRow(self._more_marker(extra))

    def _path_for(self, item):
        """Addresses from the root function down to ``item`` (for cycle detection)."""
        path = set()
        if self.cur_func is not None:
            path.add(self.cur_func.start)
        node = item
        while node is not None:
            func = getattr(node, "func", None)
            if func is not None:
                path.add(func.start)
            node = node.parent()
        return path

    def _ensure_children(self, item):
        """Populate a row's real children on first expand (idempotent)."""
        if not isinstance(item, BNFuncItem) or item.loaded or not item.expandable:
            return
        item.loaded = True
        graph = self._call_graph()
        if graph is None:
            return
        item.removeRows(0, item.rowCount())  # drop the placeholder
        self._add_children(graph, item, item.func, item.level, self._path_for(item))

    def _on_item_expanded(self, proxy_index):
        item = self.model.itemFromIndex(self.proxy_model.mapToSource(proxy_index))
        self._ensure_children(item)
        if not self._suppress_fit:
            self._fit_column()

    def _fit_column(self):
        # Size the (single) column to the widest laid-out row so the horizontal
        # scrollbar reaches the full content. Suppressed during bulk expansion so it
        # runs once at the end (not per row).
        self.treeview.resizeColumnToContents(0)

    def _expand_item(self, item):
        source_index = self.model.indexFromItem(item)
        self.treeview.expand(self.proxy_model.mapFromSource(source_index))

    def _auto_reveal(self, budget):
        """Auto-expand the tree to ``func_depth`` levels on navigation.

        Loading and expanding are two separate passes: every expandable row's
        children are loaded first (breadth-first; ``budget`` is only a safety cap for
        pathologically dense graphs), then the loaded rows are expanded. Expanding
        only after the model has stopped changing keeps earlier expansions from being
        reset by later inserts. The tree structure itself stops at ``func_depth``, so
        for normal graphs this reveals exactly the requested depth.
        """
        queue = [self.model.item(row) for row in range(self.model.rowCount())]
        while queue and self._node_count < budget:
            item = queue.pop(0)
            if not isinstance(item, BNFuncItem):
                continue
            self._ensure_children(item)
            queue.extend(item.child(row) for row in range(item.rowCount()))
        self._suppress_fit = True
        try:
            self._expand_loaded_rows()
        finally:
            self._suppress_fit = False
        self._fit_column()

    def _expand_loaded_rows(self):
        # View-only pass: expand every row whose real children are loaded. Rows that
        # still hold a placeholder (unloaded) stay collapsed, so no blank rows show.
        stack = [self.model.item(row) for row in range(self.model.rowCount())]
        while stack:
            item = stack.pop()
            if not isinstance(item, BNFuncItem) or not item.loaded:
                continue
            self._expand_item(item)
            stack.extend(item.child(row) for row in range(item.rowCount()))

    def update_widget(self, cur_func: Function, force: bool = False):
        # `force` bypasses the visibility short-circuit so callers that build a
        # one-time snapshot (e.g. pinning a tab, whose widget is not visible yet)
        # still render. The guard otherwise avoids expensive re-renders while the
        # treeview is hidden during navigation.
        if not force and not self.treeview.isVisible():
            return

        self._search_active = False  # navigation always shows the normal call tree
        self.clear()
        self.cur_func = cur_func

        graph = self._call_graph()
        if graph is None:
            return

        # Refresh cached theme brushes so runtime theme changes are picked up.
        self._brush_func = QBrush(getThemeColor(ThemeColor.CodeSymbolColor))
        self._brush_import = QBrush(getThemeColor(ThemeColor.ImportColor))

        # Build only the first level; deeper levels load lazily as rows are expanded.
        graph.expand(cur_func, direction=self._direction(), max_depth=1)
        self._add_children(
            graph, self.model.invisibleRootItem(), cur_func, 0, {cur_func.start}
        )
        # Node cap is a user setting; fall back to the constant if unset/zero.
        max_nodes = Settings().get_integer("calltree.max_nodes") or AUTO_EXPAND_NODES
        self._auto_reveal(max_nodes)

    def clear(self):
        self.model.clear()
        self._node_count = 0
        self.set_label(self.label_name)

    def set_label(self, label_name):
        self.model.setHorizontalHeaderLabels([label_name])
