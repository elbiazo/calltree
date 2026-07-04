from typing import cast
from PySide6.QtCore import QSortFilterProxyModel
from PySide6.QtGui import (
    QStandardItemModel,
    QStandardItem,
    QBrush,
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
)
from binaryninja.settings import Settings

from binaryninja import BinaryView, Function, ThemeColor
from binaryninja.enums import SymbolType
from binaryninjaui import getThemeColor


from .demangle import demangle_name
from .callgraph import get_call_graph


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
    def __init__(self, bv: BinaryView, func: Function):
        super().__init__()

        if func.symbol.type == SymbolType.FunctionSymbol:
            self.setForeground(QBrush(getThemeColor(ThemeColor.CodeSymbolColor)))
        else:
            self.setForeground(QBrush(getThemeColor(ThemeColor.ImportColor)))

        self.func = func
        self.bv = bv
        self.setText(demangle_name(self.bv, func.name))
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
        self.expand_all_button = QPushButton("+")
        self.expand_all_button.setFixedSize(btn_size)
        self.expand_all_button.clicked.connect(self.calltree.expand_all)

        self.collapse_all_button = QPushButton("-")
        self.collapse_all_button.setFixedSize(btn_size)
        self.collapse_all_button.clicked.connect(self.calltree.collapse_all)

        self.func_filter = QLineEdit()
        self.func_filter.textChanged.connect(self.calltree.onTextChanged)

        self.spinbox = QSpinBox()
        self.spinbox.valueChanged.connect(self.spinbox_changed)
        self.spinbox.setValue(self.calltree.func_depth)
        super().addWidget(self.func_filter)
        super().addWidget(self.expand_all_button)
        super().addWidget(self.collapse_all_button)
        super().addWidget(self.spinbox)

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

        self.treeview = QTreeView()
        self.model = QStandardItemModel()
        self.proxy_model = QSortFilterProxyModel(self.treeview)
        self.proxy_model.setSourceModel(self.model)
        self.treeview.setModel(self.proxy_model)
        self.treeview.setExpandsOnDoubleClick(False)

        # Single click jumps to the call site; double click drills into the function.
        self.treeview.clicked.connect(self.goto_first_func_use)
        self.treeview.doubleClicked.connect(self.goto_func)

        self.set_label(self.label_name)
        super().addWidget(self.treeview)
        self.util = CallTreeUtilLayout(self)
        super().addLayout(self.util)

    def onTextChanged(self, text):
        self.proxy_model.setRecursiveFilteringEnabled(True)
        self.proxy_model.setFilterRegularExpression(text)
        self.expand_all()

    def expand_all(self):
        self.treeview.expandAll()

    def collapse_all(self):
        self.treeview.collapseAll()

    def goto_first_func_use(self, index):
        """Single click: navigate to where the parent calls this function, without
        re-rooting the Current tab."""
        index = self.proxy_model.mapToSource(index)
        item = cast(BNFuncItem, self.model.itemFromIndex(index))
        bv = item.bv

        parent_item = cast(BNFuncItem, self.model.itemFromIndex(index.parent()))
        parent_func = parent_item.func if parent_item else self.cur_func
        if parent_func is None:
            return

        if self.is_caller:
            caller, callee = item.func, parent_func
        else:
            caller, callee = parent_func, item.func

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
        cur_func = self.model.itemFromIndex(self.proxy_model.mapToSource(index)).func
        self._request_skip_update(False)
        self.binary_view.navigate(self.binary_view.view, cur_func.start)

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

    def render_calls(self, graph, cur_func, parent_item, depth, path):
        """Populate ``parent_item`` with ``cur_func``'s neighbors from the graph.

        Recurses up to ``func_depth``. ``path`` holds the addresses on the current
        branch so cycles (e.g. ``A -> B -> A``) terminate instead of recursing.
        """
        for neighbor in graph.neighbors(cur_func, self._direction()):
            if neighbor is None:
                continue
            new_std_item = BNFuncItem(self.binary_view, neighbor)
            parent_item.appendRow(new_std_item)

            if depth < self.func_depth and neighbor.start not in path:
                self.render_calls(
                    graph, neighbor, new_std_item, depth + 1, path | {neighbor.start}
                )

    def update_widget(self, cur_func: Function, force: bool = False):
        # `force` bypasses the visibility short-circuit so callers that build a
        # one-time snapshot (e.g. pinning a tab, whose widget is not visible yet)
        # still render. The guard otherwise avoids expensive re-renders while the
        # treeview is hidden during navigation.
        if not force and not self.treeview.isVisible():
            return

        # Clear previous calls
        self.clear()
        self.cur_func = cur_func

        graph = self._call_graph()
        if graph is None:
            return

        # Lazily grow the shared graph around the current function, then render the
        # tree from it. max_depth is func_depth + 1 to cover the deepest rendered row.
        graph.expand(
            cur_func, direction=self._direction(), max_depth=self.func_depth + 1
        )

        call_root_node = self.model.invisibleRootItem()
        self.render_calls(
            graph, cur_func, call_root_node, depth=0, path={cur_func.start}
        )
        self.expand_all()

    def clear(self):
        self.model.clear()
        self.set_label(self.label_name)
        self.expand_all()

    def set_label(self, label_name):
        self.model.setHorizontalHeaderLabels([label_name])
