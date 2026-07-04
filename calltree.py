from collections import deque
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
    QPolygon,
)
from PySide6.QtCore import QSize, Qt, QTimer, QPoint
from PySide6.QtWidgets import QTreeView
from PySide6.QtWidgets import (
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QLineEdit,
    QSpinBox,
    QWidget,
    QHeaderView,
    QAbstractItemView,
    QFrame,
    QLabel,
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


def _pm_icon(color: QColor, plus: bool, size: int = 16) -> QIcon:
    """Draw a plain plus (expand) or minus (collapse) glyph — no surrounding box."""
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing, True)
    painter.setPen(QPen(color, 2))
    m = 3  # margin from the edges
    c = size // 2
    painter.drawLine(m, c, size - m, c)  # horizontal bar (minus / part of plus)
    if plus:
        painter.drawLine(c, m, c, size - m)  # vertical bar completes the plus
    painter.end()
    return QIcon(pixmap)


def _arrow_icon(color: QColor, up: bool, size: int = 16) -> QIcon:
    """Draw an up (prev) or down (next) arrow icon."""
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing, True)
    painter.setPen(QPen(color, 2))
    painter.drawLine(8, 4, 8, 12)  # shaft
    if up:
        painter.drawLine(5, 7, 8, 4)
        painter.drawLine(8, 4, 11, 7)
    else:
        painter.drawLine(5, 9, 8, 12)
        painter.drawLine(8, 12, 11, 9)
    painter.end()
    return QIcon(pixmap)


def _recursion_icon(color: QColor, size: int = 16) -> QIcon:
    """Draw a circular-arrow icon marking a recursive (cycle) call."""
    from PySide6.QtCore import QRectF

    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing, True)
    painter.setPen(QPen(color, 2))
    painter.setBrush(Qt.NoBrush)
    # ~300-degree arc leaving a gap, plus an arrowhead at the gap.
    painter.drawArc(QRectF(3, 3, 10, 10), 60 * 16, 300 * 16)
    painter.setBrush(color)
    painter.drawPolygon(QPolygon([QPoint(11, 2), QPoint(14, 6), QPoint(9, 6)]))
    painter.end()
    return QIcon(pixmap)


def _button_icon(kind: str, color: QColor, size: int = 16) -> QIcon:
    """Draw a small, theme-colored toolbar icon at runtime (``kind`` is "pin",
    "remove" or "graph"). Shared by the current-function toolbar (here) and imported
    by init.py."""
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing, True)
    painter.setPen(QPen(color, 2))
    if kind == "pin":
        painter.setBrush(color)
        # A thumbtack: a domed head above a centered downward spike.
        painter.drawEllipse(3, 1, 10, 5)
        painter.drawPolygon(QPolygon([QPoint(6, 5), QPoint(10, 5), QPoint(8, 15)]))
    elif kind == "graph":
        # Three nodes joined by edges (a mini call graph).
        top, left, right = QPoint(8, 3), QPoint(3, 13), QPoint(13, 13)
        painter.drawLine(top, left)
        painter.drawLine(top, right)
        painter.setBrush(color)
        for center in (top, left, right):
            painter.drawEllipse(center, 2, 2)
    else:  # "remove": an X
        painter.drawLine(4, 4, size - 4, size - 4)
        painter.drawLine(size - 4, 4, 4, size - 4)
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
    ``(func, name, is_match, level, is_recursive)`` for a tree bounded by ``budget``.

    With ``needle`` the tree is pruned to the paths leading to name matches
    (``is_match`` marks them) and ``found`` is False when nothing matches. With
    ``needle=None`` the full reachable tree is returned (``found`` always True).
    ``is_recursive`` marks a node that repeats an ancestor on its path (a cycle
    leaf, e.g. A -> B -> A). Touches only Binary Ninja reads, so it is safe to run
    off the main thread.
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
        is_recursive = child.start in path_set
        rows.append(
            (
                child,
                names.get(child.start, ""),
                child.start in matches,
                len(dfs),
                is_recursive,
            )
        )
        remaining -= 1
        # For a search, each branch ends at the matched function: don't descend past
        # a match. (needle is None => the full "expand all" tree, always descend.)
        ends_here = needle is not None and child.start in matches
        if not ends_here and not is_recursive:
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


class MoreItem(QStandardItem):
    """The clickable "… N more" overflow row under a node whose child count exceeds
    ``MAX_CHILDREN_PER_NODE``. Clicking it loads all remaining children (see
    ``CallTreeLayout._load_more``)."""

    is_more = True

    def __init__(self, count, parent_item, parent_func, parent_level, path, shown):
        super().__init__(f"… {count} more")
        self.setEditable(False)
        self.parent_item = parent_item
        self.parent_func = parent_func
        self.parent_level = parent_level
        self.path = path
        self.shown = shown


class _FuncNameLineEdit(QLineEdit):
    """Read-only function-name field for the current-function row. Because the box is
    pinned to the (narrow) search-box width, a long name is shown from the start and its
    full text is exposed as a tooltip. Clicks are routed to the preview / commit
    callbacks."""

    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
        self.setAlignment(Qt.AlignLeft)
        self._on_click = None
        self._on_double = None

    def setText(self, text):
        super().setText(text)
        self.setCursorPosition(0)  # show the start of a long name, not the end
        self.setToolTip(text)  # full name on hover

    def mousePressEvent(self, event):
        if self._on_click is not None:
            self._on_click(event)

    def mouseDoubleClickEvent(self, event):
        if self._on_double is not None:
            self._on_double(event)


class CurrentFunctionNameLayout(QHBoxLayout):
    """Header showing the pane's root function. Clicking mirrors the call trees: a
    single click previews (navigate the main view without re-rooting the Current
    tab), a double click commits (navigate and re-root the Current tab)."""

    def __init__(self, sidebar=None):
        super().__init__()
        self.sidebar = sidebar
        self.binary_view = None
        # A read-only line edit that stretches to fill the row (buttons stay right-
        # aligned); long names show from the start and expose the full text as a tooltip.
        self.cur_func_text = _FuncNameLineEdit()
        self.cur_func_text._on_click = self.preview_func
        self.cur_func_text._on_double = self.goto_func
        super().addWidget(self.cur_func_text, 1)  # stretch so buttons stay right-aligned
        self._add_toolbar()

    def _add_toolbar(self):
        """Graph / pin / close buttons on the current-function row, right-aligned and
        styled like the per-pane search toolbar (25x25). They drive the owning
        sidebar, so they are only added when one is present."""
        if self.sidebar is None:
            return
        btn_size = QSize(25, 25)
        icon_color = self.cur_func_text.palette().color(QPalette.ButtonText)

        self.graph_button = QPushButton()
        self.graph_button.setIcon(_button_icon("graph", icon_color))
        self.graph_button.setToolTip(
            "Open a call graph of the functions currently shown in both trees"
        )
        self.graph_button.setFixedSize(btn_size)
        self.graph_button.clicked.connect(self.sidebar.create_call_graph)

        self.pin_button = QPushButton()
        self.pin_button.setIcon(_button_icon("pin", icon_color))
        self.pin_button.setToolTip("Pin the current call tree in a new tab")
        self.pin_button.setFixedSize(btn_size)
        self.pin_button.clicked.connect(self.sidebar.pin_current_tab)

        self.close_button = QPushButton()
        self.close_button.setIcon(_button_icon("remove", icon_color))
        self.close_button.setToolTip("Remove the active pinned tab")
        self.close_button.setFixedSize(btn_size)
        self.close_button.clicked.connect(self.sidebar.remove_current_tab)

        separator = QFrame()
        separator.setFrameShape(QFrame.VLine)
        separator.setFrameShadow(QFrame.Sunken)

        # [function box ··········] (space) [graph] | [pin] [close]
        self.addSpacing(8)  # gap between the current-function box and the graph button
        self.addWidget(self.graph_button)
        self.addSpacing(6)
        self.addWidget(separator)
        self.addSpacing(6)
        self.addWidget(self.pin_button)
        self.addWidget(self.close_button)

    # TODO: really should check the address as well as name; matching on name alone can fail.
    def _lookup_func(self):
        if self.binary_view is None:
            return None
        funcs = self.binary_view.get_functions_by_name(self.cur_func_text.text())
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
        # Search is explicit (press Enter), not per-keystroke.
        self.func_filter.returnPressed.connect(self.trigger_search)
        # Built-in clear (x) button, shown only while there's text; clearing it drops
        # the search and restores the normal call tree.
        self.func_filter.setClearButtonEnabled(True)
        self.func_filter.textChanged.connect(self._on_search_text_changed)

        # "cur of total" match counter, shown to the right of the search box only while
        # a search is active (blank during normal browsing so an idle "0 of 0" is never
        # mistaken for a failed search). A persistent min-width keeps the slot stable.
        self.match_label = QLabel("")
        self.match_label.setToolTip("Current match / total matches")
        self.match_label.setAlignment(Qt.AlignCenter)
        self.match_label.setMinimumWidth(52)

        self.prev_button = QPushButton()
        self.prev_button.setIcon(_arrow_icon(icon_color, up=True))
        self.prev_button.setToolTip("Previous match")
        self.prev_button.setFixedSize(btn_size)
        self.prev_button.clicked.connect(self.calltree.prev_match)

        self.next_button = QPushButton()
        self.next_button.setIcon(_arrow_icon(icon_color, up=False))
        self.next_button.setToolTip("Next match")
        self.next_button.setFixedSize(btn_size)
        self.next_button.clicked.connect(self.calltree.next_match)

        super().addWidget(self.func_filter)
        super().addWidget(self.match_label)
        super().addSpacing(6)  # gap before the prev/next match buttons
        super().addWidget(self.prev_button)
        super().addWidget(self.next_button)

    def set_match_count(self, cur, total):
        self.match_label.setText(f"{cur} of {total}")

    def clear_match_count(self):
        self.match_label.setText("")

    def trigger_search(self):
        self.calltree.do_search(self.func_filter.text())

    def _on_search_text_changed(self, text):
        # When the box is emptied (clear button or deleting), drop the active search and
        # restore the normal call tree. Non-empty edits still wait for Enter / the button.
        if not text:
            self.calltree.do_search("")


# Per-pane header: the "<direction> Calls" label plus the depth + expand/collapse
# controls (moved here from the search toolbar), sized like the search row.
class CallTreeHeaderLayout(QHBoxLayout):
    def __init__(self, calltree: "CallTreeLayout", label_name: str):
        super().__init__()
        self.calltree = calltree
        btn_size = QSize(25, 25)
        icon_color = calltree.treeview.palette().color(QPalette.ButtonText)

        self.label = QLabel(label_name)

        self.spinbox = QSpinBox()
        self.spinbox.valueChanged.connect(self.spinbox_changed)
        self.spinbox.setValue(calltree.func_depth)

        self.expand_all_button = QPushButton()
        self.expand_all_button.setIcon(_pm_icon(icon_color, plus=True))
        self.expand_all_button.setToolTip("Expand the full call subtree")
        self.expand_all_button.setFixedSize(btn_size)
        self.expand_all_button.clicked.connect(calltree.expand_all)

        self.collapse_all_button = QPushButton()
        self.collapse_all_button.setIcon(_pm_icon(icon_color, plus=False))
        self.collapse_all_button.setToolTip("Collapse all")
        self.collapse_all_button.setFixedSize(btn_size)
        self.collapse_all_button.clicked.connect(calltree.collapse_all)

        # [<direction> Calls ················] [depth] (space) [⊞] [⊟]
        super().addWidget(self.label)
        super().addStretch(1)
        super().addWidget(self.spinbox)
        super().addSpacing(6)  # gap between the depth box and the expand button
        super().addWidget(self.expand_all_button)
        super().addWidget(self.collapse_all_button)

    def spinbox_changed(self):
        self.calltree.func_depth = self.spinbox.value()
        if self.calltree.cur_func is not None:
            self.calltree.update_widget(self.calltree.cur_func)


class _CalltreeTreeView(QTreeView):
    """QTreeView that re-applies its column width on resize *and* on show so the single
    column keeps spanning at least the viewport (uniform row/header background, no dead
    white strip on the right) while still overflowing into a horizontal scroll for long
    names. The show hook matters for pinned tabs, which are built while hidden (viewport
    width 0) and are not otherwise re-fit when first displayed."""

    def __init__(self):
        super().__init__()
        self._on_resize = None

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self._on_resize is not None:
            self._on_resize()

    def showEvent(self, event):
        super().showEvent(event)
        if self._on_resize is not None:
            self._on_resize()


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
        self._match_items = []
        self._match_index = -1
        self._brush_func = None
        self._brush_import = None
        self._recursion_qicon = None
        # Bumped whenever the model is cleared/rebuilt; a running _auto_reveal captures
        # it and bails if it changes (the items it holds have been deleted underneath).
        self._build_gen = 0
        self._content_width = 0  # widest laid-out row (see _fit_column)

        self.treeview = _CalltreeTreeView()
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
        self.treeview.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.treeview.setTextElideMode(Qt.ElideNone)
        # The "<direction> Calls" label lives in the header row now (with the depth +
        # expand/collapse controls), so hide the tree's own column header.
        self.treeview.setHeaderHidden(True)

        # Single click jumps to the call site; double click drills into the function.
        self.treeview.clicked.connect(self.goto_first_func_use)
        self.treeview.doubleClicked.connect(self.goto_func)
        # Lazily populate a row's children the first time it is expanded.
        self.treeview.expanded.connect(self._on_item_expanded)
        # Keep the column spanning the viewport as the pane is resized.
        self.treeview._on_resize = self._on_viewport_resized

        self.set_label(self.label_name)
        self.header = CallTreeHeaderLayout(self, self.label_name)
        super().addLayout(self.header)
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
        if not found or not rows:
            self._append_info(root, "No matches")
            self._update_match_counter()
            return
        self._ensure_brushes()
        # Rebuild the pruned tree from the pre-order (func, name, is_match, level,
        # is_recursive) rows, collecting the match rows (in reading order) for
        # prev/next cycling.
        parents = {0: root}
        for func, name, is_match, level, is_recursive in rows:
            item = BNFuncItem(func, name, self._brush_for(func), level)
            self._node_count += 1
            if is_recursive:
                item.setIcon(self._recursion_qicon)
            if is_match:
                font = item.font()
                font.setBold(True)
                item.setFont(font)
                self._match_items.append(item)
            parents.get(level - 1, root).appendRow(item)
            parents[level] = item
        self._suppress_fit = True
        try:
            self.treeview.expandAll()
        finally:
            self._suppress_fit = False
        self._fit_column()
        if self._match_items:  # auto-select the first match
            self._match_index = 0
            self._select_match()

    def next_match(self):
        self._step_match(1)

    def prev_match(self):
        self._step_match(-1)

    def _step_match(self, delta):
        if not self._match_items:
            return
        self._match_index = (self._match_index + delta) % len(self._match_items)
        self._select_match()

    def _select_match(self):
        # Highlight + scroll to the current match. Does not navigate the disassembly
        # view (double-click still does that); this is pure in-tree navigation.
        self._update_match_counter()
        item = self._match_items[self._match_index]
        proxy_index = self.proxy_model.mapFromSource(self.model.indexFromItem(item))
        if not proxy_index.isValid():
            return
        self.treeview.setCurrentIndex(proxy_index)
        # Defer the centering scroll: right after expandAll the view has not finished
        # laying rows out, so an immediate scrollTo uses stale positions and the
        # match lands off-center. Running it on the next event-loop turn centers it.
        QTimer.singleShot(0, self._center_current_match)

    def _center_current_match(self):
        if not (0 <= self._match_index < len(self._match_items)):
            return
        item = self._match_items[self._match_index]
        proxy_index = self.proxy_model.mapFromSource(self.model.indexFromItem(item))
        if not proxy_index.isValid():
            return
        self.treeview.scrollTo(proxy_index, QAbstractItemView.PositionAtCenter)
        # scrollTo centers vertically but jams a deeply-indented (far-right) match to
        # the right edge horizontally. Re-center the match's left edge (the start of
        # its name) in the viewport so it isn't lost off-screen on wide trees.
        hbar = self.treeview.horizontalScrollBar()
        rect = self.treeview.visualRect(proxy_index)
        viewport_w = self.treeview.viewport().width()
        item_left = rect.left() + hbar.value()  # absolute x in content coords
        hbar.setValue(max(0, item_left - viewport_w // 2))

    def _update_match_counter(self):
        if not hasattr(self, "util"):
            return
        # The counter is a search indicator: only show it while a search is active, so
        # a normal (unsearched) call tree never sits next to a misleading "0 of 0".
        if not self._search_active:
            self.util.clear_match_count()
            return
        total = len(self._match_items)
        cur = self._match_index + 1 if total else 0
        self.util.set_match_count(cur, total)

    def _show_info(self, text):
        self._reset_model()
        self._append_info(self.model.invisibleRootItem(), text)

    def _append_info(self, root, text):
        item = QStandardItem(text)
        item.setEditable(False)
        item.setSelectable(False)
        root.appendRow(item)

    def _reset_model(self):
        self._build_gen += 1
        self.proxy_model.setFilterRegularExpression("")
        self.model.clear()
        self._node_count = 0
        self._match_items = []
        self._match_index = -1
        self._update_match_counter()
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
        self._show_info("Loading…")  # feedback while the full (big) tree walk runs
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
            if not rows:  # no callers / callees in this direction
                self._append_info(root, "No functions")
                return
            parents = {0: root}
            for func, name, _is_match, level, is_recursive in rows:
                item = BNFuncItem(func, name, self._brush_for(func), level)
                self._node_count += 1
                if is_recursive:
                    item.setIcon(self._recursion_qicon)
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
        if getattr(item, "is_more", False):  # "… N more" row: load the rest
            self._load_more(item)
            return
        func = getattr(item, "func", None)
        if func is None:  # a placeholder row, not a function row
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
        if self._recursion_qicon is None:
            color = self.treeview.palette().color(QPalette.WindowText)
            self._recursion_qicon = _recursion_icon(color)

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

    def _add_children(
        self,
        graph,
        parent_item,
        parent_func,
        parent_level,
        path,
        start=0,
        limit=MAX_CHILDREN_PER_NODE,
    ):
        """Add ``parent_func``'s direct neighbors under ``parent_item`` (one level).

        A child that can be expanded further gets a placeholder child so its expand
        arrow appears (regardless of ``func_depth`` — the depth cap only bounds
        *auto*-expansion, so the user can always drill one level deeper). A child that
        repeats an ancestor (cycle, e.g. A -> B -> A) is a leaf marked with the
        recursion icon. ``start``/``limit`` page the neighbor list (``limit=None`` loads
        all remaining); when more remain a clickable "… N more" row is appended (see
        _load_more).
        """
        self._ensure_brushes()
        graph.expand(parent_func, direction=self._direction(), max_depth=1)
        neighbors = [
            n for n in graph.neighbors(parent_func, self._direction()) if n is not None
        ]
        child_level = parent_level + 1
        end = len(neighbors) if limit is None else start + limit
        for neighbor in neighbors[start:end]:
            item = self._make_item(graph, neighbor, child_level)
            parent_item.appendRow(item)
            if neighbor.start in path:
                # Recursive call back to an ancestor: leaf marked with the icon.
                item.setIcon(self._recursion_qicon)
            elif self._has_neighbors(graph, neighbor):
                item.appendRow(self._placeholder())
                item.expandable = True
        remaining = len(neighbors) - end
        if remaining > 0:
            parent_item.appendRow(
                MoreItem(remaining, parent_item, parent_func, parent_level, path, end)
            )

    def _load_more(self, more_item):
        """Replace a "… N more" row with all remaining children of its node."""
        graph = self._call_graph()
        if graph is None:
            return
        parent_item = more_item.parent_item
        parent_item.removeRow(more_item.row())
        self._add_children(
            graph,
            parent_item,
            more_item.parent_func,
            more_item.parent_level,
            more_item.path,
            start=more_item.shown,
            limit=None,
        )
        self._fit_column()

    def collect_edges(self):
        """Directed ``(caller_func, callee_func)`` pairs for every function currently
        shown in this tree (used to build the FlowGraph). Direction follows the pane:
        outgoing = parent -> child, incoming = child -> parent. Placeholder / "… more"
        rows (no ``func``) are skipped. The root function is the parent of top-level
        rows."""
        edges = []
        root = self.model.invisibleRootItem()
        stack = [root.child(row) for row in range(root.rowCount())]
        while stack:
            item = stack.pop()
            if not isinstance(item, BNFuncItem):
                continue
            parent_item = item.parent()
            parent_func = getattr(parent_item, "func", None) or self.cur_func
            if parent_func is not None and item.func is not None:
                if self.is_caller:
                    edges.append((item.func, parent_func))
                else:
                    edges.append((parent_func, item.func))
            stack.extend(item.child(row) for row in range(item.rowCount()))
        return edges

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
        # Size the (single) column to the widest laid-out row, but never below the
        # viewport width, so the row / selection / header background fills the whole
        # pane (uniform color, no dead white strip on the right) while long names still
        # overflow into a horizontal scroll. Suppressed during bulk expansion so it
        # runs once at the end (not per row).
        self.treeview.resizeColumnToContents(0)
        self._content_width = self.treeview.columnWidth(0)
        self._apply_min_column_width()

    def _apply_min_column_width(self):
        viewport_w = self.treeview.viewport().width()
        target = max(self._content_width, viewport_w)
        if self.treeview.columnWidth(0) != target:
            self.treeview.setColumnWidth(0, target)

    def _on_viewport_resized(self):
        # On pane resize just re-apply the min width (cheap; no content re-measure).
        self._apply_min_column_width()

    def _expand_item(self, item):
        source_index = self.model.indexFromItem(item)
        self.treeview.expand(self.proxy_model.mapFromSource(source_index))

    def _auto_reveal(self, budget):
        """Auto-expand the tree to ``func_depth`` levels on navigation.

        Loading and expanding are two separate passes: expandable rows up to
        ``func_depth`` are loaded first (breadth-first; ``budget`` is a safety cap for
        pathologically dense graphs), then the loaded rows are expanded. Expanding
        only after the model has stopped changing keeps earlier expansions from being
        reset by later inserts. Auto-expansion stops at ``func_depth``; deeper rows
        keep their expand arrow so the user can still drill down manually.

        Guarded by ``_build_gen``: if a re-entrant navigation/search rebuilds the model
        while this runs, the items held here are deleted, so the traversal aborts
        rather than touching a freed C++ object.
        """
        gen = self._build_gen
        # deque (O(1) popleft) not a list (O(n) pop(0)) so the BFS stays linear even
        # for large auto-expand budgets (calltree.max_nodes in the thousands).
        queue = deque(self.model.item(row) for row in range(self.model.rowCount()))
        while queue and self._node_count < budget:
            if self._build_gen != gen:
                return  # model was rebuilt underneath us; our items are stale
            item = queue.popleft()
            try:
                # Load a row's children only if the row is shallower than func_depth, so
                # the deepest auto-created level is exactly func_depth (loading a level-N
                # row creates level N+1). Deeper rows keep their arrow for manual expand.
                if not isinstance(item, BNFuncItem) or item.level >= self.func_depth:
                    continue
                self._ensure_children(item)
                queue.extend(item.child(row) for row in range(item.rowCount()))
            except RuntimeError:
                return  # a held item's C++ object was deleted; stop the stale walk
        if self._build_gen != gen:
            return
        self._suppress_fit = True
        try:
            self._expand_loaded_rows()
        finally:
            self._suppress_fit = False
        self._fit_column()

    def _expand_loaded_rows(self):
        # View-only pass: expand every row whose real children are loaded. Rows that
        # still hold a placeholder (unloaded) stay collapsed, so no blank rows show.
        gen = self._build_gen
        stack = [self.model.item(row) for row in range(self.model.rowCount())]
        while stack:
            if self._build_gen != gen:
                return
            item = stack.pop()
            try:
                if not isinstance(item, BNFuncItem) or not item.loaded:
                    continue
                self._expand_item(item)
                stack.extend(item.child(row) for row in range(item.rowCount()))
            except RuntimeError:
                return

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

        if self.func_depth <= 0:
            # Depth 0 = show nothing (so an exported call graph reflects an empty pane).
            self._append_info(self.model.invisibleRootItem(), "Depth is 0")
            return

        graph = self._call_graph()
        if graph is None:
            return

        # Refresh cached theme brushes so runtime theme changes are picked up.
        self._brush_func = QBrush(getThemeColor(ThemeColor.CodeSymbolColor))
        self._brush_import = QBrush(getThemeColor(ThemeColor.ImportColor))

        # Build only the first level; deeper levels load lazily as rows are expanded.
        graph.expand(cur_func, direction=self._direction(), max_depth=1)
        root = self.model.invisibleRootItem()
        self._add_children(graph, root, cur_func, 0, {cur_func.start})
        if root.rowCount() == 0:  # no callers / callees in this direction
            self._append_info(root, "No functions")
            return
        # Node cap is a user setting; fall back to the constant if unset/zero.
        max_nodes = Settings().get_integer("calltree.max_nodes") or AUTO_EXPAND_NODES
        self._auto_reveal(max_nodes)

    def clear(self):
        self._build_gen += 1
        self.model.clear()
        self._node_count = 0
        self._match_items = []
        self._match_index = -1
        self._update_match_counter()
        self.set_label(self.label_name)

    def set_label(self, label_name):
        self.model.setHorizontalHeaderLabels([label_name])
