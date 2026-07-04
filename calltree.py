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
    def __init__(self):
        super().__init__()
        calltree_layout = QVBoxLayout()
        # Add widgets to the layout
        in_func_depth = Settings().get_integer("calltree.in_depth")
        out_func_depth = Settings().get_integer("calltree.out_depth")

        self.in_calltree = CallTreeLayout("Incoming Calls", in_func_depth, True)
        self.out_calltree = CallTreeLayout("Outgoing Calls", out_func_depth, False)
        self.cur_func_layout = CurrentFunctionNameLayout()

        self.cur_func_text = self.cur_func_layout.cur_func_text

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
    def __init__(self):
        super().__init__()
        self._binary_view = None
        self.cur_func_text = QTextEdit()
        self.cur_func_text.setReadOnly(True)
        self.cur_func_text.setMaximumHeight(30)
        self.cur_func_text.setAlignment(Qt.AlignLeft | Qt.AlignTop)
        self.cur_func_text.setLineWrapMode(QTextEdit.NoWrap)
        self.cur_func_text.mousePressEvent = self.goto_func

        super().addWidget(self.cur_func_text)

    @property
    def binary_view(self):
        return self._binary_view

    @binary_view.setter
    def binary_view(self, bv):
        self._binary_view = bv

    # TODO: really should check the address as well as name. just going to function name might fail
    def goto_func(self, event):
        # just get the first one
        cur_func = self._binary_view.get_functions_by_name(
            self.cur_func_text.toPlainText()
        )[0]
        # make sure that sidebar is updated
        self._binary_view.navigate(self._binary_view.view, cur_func.start)


# Layout with search bar and expand/collapse buttons
# Takes CallTreeLayout as a parameter
class CallTreeUtilLayout(QHBoxLayout):
    def __init__(self, calltree: object):
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

    def __init__(self, label_name: str, depth: int, is_caller: bool):
        super().__init__()
        self._cur_func = None
        self._is_caller = is_caller
        self._skip_update = False

        # Creates treeview for all the function calls
        self._treeview = QTreeView()
        self._model = QStandardItemModel()
        self._proxy_model = QSortFilterProxyModel(self.treeview)
        self.proxy_model.setSourceModel(self.model)

        self.treeview.setModel(self.proxy_model)
        self.treeview.setExpandsOnDoubleClick(False)

        # Clicking function on treeview will take you to the function
        self.treeview.clicked.connect(self.goto_first_func_use)
        self.treeview.doubleClicked.connect(self.goto_func)

        self._func_depth = depth
        self._binary_view = None
        self._label_name = label_name
        self.set_label(self.label_name)
        super().addWidget(self.treeview)
        self.util = CallTreeUtilLayout(self)
        super().addLayout(self.util)

    def onTextChanged(self, text):
        self.proxy_model.setRecursiveFilteringEnabled(True)
        self.proxy_model.setFilterRegularExpression(text)
        self.expand_all()

    @property
    def proxy_model(self):
        return self._proxy_model

    @property
    def label_name(self):
        return self._label_name

    @property
    def cur_func(self):
        return self._cur_func

    @cur_func.setter
    def cur_func(self, cur_func):
        self._cur_func = cur_func

    @property
    def is_caller(self):
        return self._is_caller

    @property
    def treeview(self):
        return self._treeview

    @property
    def model(self):
        return self._model

    @property
    def binary_view(self):
        return self._binary_view

    @binary_view.setter
    def binary_view(self, bv):
        self._binary_view = bv

    @property
    def func_depth(self):
        return self._func_depth

    @func_depth.setter
    def func_depth(self, depth):
        self._func_depth = depth

    @property
    def skip_update(self) -> bool:
        """
        Tells parent view that it should skip updating the sidebar.
        Parent will then set it True once it has been skipped
        """
        return self._skip_update

    @skip_update.setter
    def skip_update(self, value: bool):
        self._skip_update = value

    def get_treeview(self):
        return self.treeview

    def expand_all(self):
        self.treeview.expandAll()

    def collapse_all(self):
        self.treeview.collapseAll()

    def goto_first_func_use(self, index):
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
            # callee not found in callers
            return

        self._skip_update = True
        self._binary_view.navigate(self._binary_view.view, ref.address)

    def goto_func(self, index):
        cur_func = self.model.itemFromIndex(self.proxy_model.mapToSource(index)).func
        # make sure that sidebar is updated
        self._skip_update = False
        self._binary_view.navigate(self._binary_view.view, cur_func.start)

    def _direction(self) -> str:
        """Graph traversal direction for this tree (incoming calls == callers)."""
        return "callers" if self.is_caller else "callees"

    def _call_graph(self):
        """Return the shared CallGraph for the current view, or None if unavailable."""
        bv = self._binary_view
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
            new_std_item = BNFuncItem(self._binary_view, neighbor)
            parent_item.appendRow(new_std_item)

            if depth < self._func_depth and neighbor.start not in path:
                self.render_calls(
                    graph, neighbor, new_std_item, depth + 1, path | {neighbor.start}
                )

    def update_widget(self, cur_func: Function):
        if not self.treeview.isVisible():
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
            cur_func, direction=self._direction(), max_depth=self._func_depth + 1
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
