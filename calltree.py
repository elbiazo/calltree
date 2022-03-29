from pathlib import Path
from PySide6.QtCore import QSortFilterProxyModel
from PySide6.QtGui import (
    QStandardItemModel,
    QStandardItem,
    QIcon
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
)

CallTreeFormat  = {
    "Top Down (Display Current Function)": 0,
    "Top Down" : 1,
    "Bottom Up": 2,
}

class BNFuncItem(QStandardItem):
    def __init__(self, func):
        super().__init__()
        self.func = func
        self.setText(func.name)
        self.setEditable(False)


class CurrentFunctionLayout(QHBoxLayout):
    def __init__(self):
        super().__init__()
        self.cur_func_text = QTextEdit()
        self.cur_func_text.setReadOnly(True)
        self.cur_func_text.setMaximumHeight(40)
        self.cur_func_text.setAlignment(Qt.AlignLeft | Qt.AlignTop)
        self.cur_func_text.setLineWrapMode(QTextEdit.NoWrap)
        super().addWidget(self.cur_func_text)


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

        root = Path(__file__).parent
        # Lock icons created by Freepik - Flaticon
        self.lock_icon = QIcon(str(root.joinpath("locked.png")))
        self.unlock_icon = QIcon(str(root.joinpath("unlocked.png")))

        self.lock_table_button = QPushButton()
        self.lock_table_button.setFixedSize(btn_size)
        self.lock_table_button.clicked.connect(self.lockbutton_changed)
        self.lockbutton_state = False
        self.lock_table_button.setIcon(self.unlock_icon)
        self.lock_table_button.setIconSize(QSize(15, 15))

        self.spinbox = QSpinBox()
        self.spinbox.valueChanged.connect(self.spinbox_changed)
        self.spinbox.setValue(self.calltree.func_depth)
        super().addWidget(self.func_filter)
        super().addWidget(self.lock_table_button)
        super().addWidget(self.expand_all_button)
        super().addWidget(self.collapse_all_button)
        super().addWidget(self.spinbox)

    def spinbox_changed(self):
        self.calltree.func_depth = self.spinbox.value()
        if self.calltree.cur_func is not None:
            self.calltree.update_widget(self.calltree.cur_func)

    def lockbutton_changed(self):
        self.lockbutton_state = ~self.lockbutton_state
        self.calltree._lock_table = self.lockbutton_state
        if(self.lockbutton_state):
            self.lock_table_button.setIcon(self.lock_icon)
        else:
            self.lock_table_button.setIcon(self.unlock_icon)
            bv = self.calltree.get_bv()
            self.calltree.update_widget(bv.get_function_at(bv.offset))

class CallTreeLayout(QVBoxLayout):
    def __init__(self, label_name: str, depth: int, is_caller: bool):
        super().__init__()
        self._cur_func = None
        self._lock_table = False
        self._is_caller = is_caller
        self._calltree_format = None
        # Creates treeview for all the function calls
        self._treeview = QTreeView()
        self._model = QStandardItemModel()
        self._proxy_model = QSortFilterProxyModel(self.treeview)
        self.proxy_model.setSourceModel(self.model)

        self.treeview.setModel(self.proxy_model)

        # Clicking function on treeview will take you to the function
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
    def calltree_format(self):
        return self._calltree_format

    @calltree_format.setter
    def calltree_format(self, calltree_format):
        self._calltree_format = calltree_format

    @property
    def treeview(self):
        return self._treeview

    @property
    def func_depth(self):
        return self._func_depth

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

    def get_treeview(self):
        return self.treeview

    def expand_all(self):
        self.treeview.expandAll()

    def collapse_all(self):
        self.treeview.collapseAll()

    def goto_func(self, index):
        cur_func = self.model.itemFromIndex(self.proxy_model.mapToSource(index)).func
        self._binary_view.navigate(self._binary_view.view, cur_func.start)

    def get_bv(self):
        return self._binary_view

    def set_func_calls(self, cur_func, cur_std_item, is_caller: bool, depth=0):
        if is_caller:
            cur_func_calls = list(set(cur_func.callers))
        else:
            cur_func_calls = list(set(cur_func.callees))

        if depth < self._func_depth:
            if cur_func_calls:
                for cur_func_call in cur_func_calls:
                    new_std_item = BNFuncItem(cur_func_call)
                    cur_std_item.appendRow(new_std_item)

                    # Dont search on function that calls itself
                    if cur_func != cur_func_call:
                        self.set_func_calls(
                            cur_func_call, new_std_item, is_caller, depth + 1
                        )

    def update_widget(self, cur_func):
        if self._lock_table:
            return

        # Clear previous calls
        self.clear()
        call_root_node = self.model.invisibleRootItem()

        if self.is_caller:
            cur_func_calls = list(set(cur_func.callers))
        else:
            cur_func_calls = list(set(cur_func.callees))

        root_std_items = []

        # Set root std Items
        if cur_func_calls:
            for cur_func_call in cur_func_calls:
                if (CallTreeFormat[self.calltree_format] == 0): # display current function
                    root_std_items.append(BNFuncItem(cur_func))
                    root_std_items[-1].appendRow(BNFuncItem(cur_func_call))
                else:
                    root_std_items.append(BNFuncItem(cur_func_call))
                cur_std_item = root_std_items[-1]
                if cur_func != cur_func_call:
                    self.set_func_calls(cur_func_call, cur_std_item, self.is_caller)

        if (CallTreeFormat[self.calltree_format] == 0 or CallTreeFormat[self.calltree_format] == 1):
            reversed = self.reverse_tree(root_std_items)
            call_root_node.appendRows(reversed)
        else:
            call_root_node.appendRows(root_std_items)
        self.expand_all()

    def reverse_tree(self, tree):
        tmp = {}
        reversed = []

        for idx, item in enumerate(tree):
            tmp[idx] = [item.func]
            self.walk_tree(item, tmp, idx)

        for idx, lst in tmp.items():
            item = BNFuncItem(lst.pop())
            for idx in range(0, len(lst)):
                self.append_to_lowest_child(item, BNFuncItem(lst.pop()))
            reversed.append(item)

        return reversed

    def walk_tree(self, item, dict, idx):
        for row in range(item.rowCount()):
            dict[idx].append(item.child(row).func)
            self.walk_tree(item.child(row), dict, idx)

    def append_to_lowest_child(self, item, value):
        if not item.rowCount():
            item.appendRow(value)
        else:
            for i in range(0, item.rowCount()):
                child = item.child(i, 0)
                self.append_to_lowest_child(child, value)

    def clear(self):
        self.model.clear()
        self.set_label(self.label_name)
        self.expand_all()

    def set_label(self, label_name):
        self.model.setHorizontalHeaderLabels([label_name])
