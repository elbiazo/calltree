from PySide6.QtCore import Qt, QRectF, QSortFilterProxyModel
from PySide6.QtWidgets import (
    QApplication,
    QTreeView,
    QWidget,
    QLabel,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
)
from PySide6.QtGui import (
    QFont,
    QColor,
    QStandardItemModel,
    QStandardItem,
    QImage,
    QPixmap,
    QPainter,
    QIcon,
)

class BNFuncItem(QStandardItem):
    def __init__(self, func, depth_num=0):
        super().__init__()
        self.func = func
        self.setText(func.name)

class CallTreeWidget:
    def __init__(self, label_name):
        self.treeview = QTreeView()
        self.model = QStandardItemModel()
        self.proxy_model = QSortFilterProxyModel(self.treeview)
        self.proxy_model.setSourceModel(self.model)

        self.treeview.setModel(self.proxy_model)
        self.treeview.doubleClicked.connect(self.goto_func)
        self.func_depth = 1
        self._binary_view = None
        self.label_name = label_name
        self.set_label(self.label_name)

    def onTextChanged(self, text):
        self.proxy_model.setFilterRegularExpression(text)

    @property
    def binary_view(self):
        return self._binary_view

    @binary_view.setter
    def binary_view(self, bv):
        self._binary_view = bv

    def get_treeview(self):
        return self.treeview

    def expand_all(self):
        self.treeview.expandAll()

    def goto_func(self, index):
        cur_item_index = self.treeview.selectedIndexes()[0]
        cur_func = cur_item_index.model().itemFromIndex(index).func
        self._binary_view.navigate(self._binary_view.view, cur_func.start)

    def set_func_calls(self, cur_func, cur_std_item, is_caller: bool, depth=0):
        if is_caller:
            cur_func_calls = list(set(cur_func.callers))
        else:
            cur_func_calls = list(set(cur_func.callees))

        if depth < self.func_depth:
            if cur_func_calls:
                for cur_func_call in cur_func_calls:
                    new_std_item = BNFuncItem(cur_func_call, depth)
                    cur_std_item.appendRow(new_std_item)
                    self.set_func_calls(
                        cur_func_call, new_std_item, is_caller, depth + 1
                    )

    def update_widget(self, cur_func, is_caller):
        # Clear previous calls
        self.clear()
        call_root_node = self.model.invisibleRootItem()

        if is_caller:
            cur_func_calls = list(set(cur_func.callers))
        else:
            cur_func_calls = list(set(cur_func.callees))

        root_std_items = []

        # Set root std Items
        if cur_func_calls:
            for cur_func_call in cur_func_calls:
                root_std_items.append(BNFuncItem(cur_func_call))
                cur_std_item = root_std_items[-1]
                self.set_func_calls(cur_func_call, cur_std_item, is_caller)

        call_root_node.appendRows(root_std_items)

    def clear(self):
        self.model.clear()
        self.set_label(self.label_name)

    def set_label(self, label_name):
        self.model.setHorizontalHeaderLabels([label_name])
