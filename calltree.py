from PySide6.QtCore import QSortFilterProxyModel
from PySide6.QtGui import (
    QStandardItemModel,
    QStandardItem,
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


class BNFuncItem(QStandardItem):
    def __init__(self, func):
        super().__init__()
        self.func = func
        self.setText(func.name)


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
    def __init__(self, label_name: str, depth: int, is_caller: bool):
        super().__init__()
        self._cur_func = None
        self._is_caller = is_caller
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
                root_std_items.append(BNFuncItem(cur_func_call))
                cur_std_item = root_std_items[-1]
                if cur_func != cur_func_call:
                    self.set_func_calls(cur_func_call, cur_std_item, self.is_caller)

        call_root_node.appendRows(root_std_items)
        self.expand_all()

    def clear(self):
        self.model.clear()
        self.set_label(self.label_name)
        self.expand_all()

    def set_label(self, label_name):
        self.model.setHorizontalHeaderLabels([label_name])
