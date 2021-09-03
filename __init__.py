from binaryninjaui import DockHandler, DockContextHandler, UIActionHandler
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QTreeView,
    QWidget,
    QLabel,
    QVBoxLayout,
)
from PySide6.QtGui import QFont, QColor, QStandardItemModel, QStandardItem


class StandardItem(QStandardItem):
    def __init__(self, txt="", font_size=12, set_bold=False, color=QColor(0, 0, 0)):
        super().__init__()

        fnt = QFont("Open Sans", font_size)
        fnt.setBold(set_bold)

        self.setEditable(False)

        # Todo: Add support for binja color
        # self.setForeground(color)
        self.setFont(fnt)
        self.setText(txt)


class CallTreeWidget(QWidget, DockContextHandler):
    def __init__(self, parent, name):
        QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)
        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)
        self.cur_func = None
        self.prev_func_offset = None
        self.binary_view = None
        self.func_depth = 10

        # Create a QHBoxLayout instance
        call_layout = QVBoxLayout()
        # Add widgets to the layout
        self.incall_tree_view = QTreeView()
        self.outcall_tree_view = QTreeView()

        self.incall_tree_model = QStandardItemModel()
        self.outcall_tree_model = QStandardItemModel()

        self.incall_tree_view.setModel(self.incall_tree_model)
        self.outcall_tree_view.setModel(self.outcall_tree_model)
        cur_func_layout = QVBoxLayout()
        self.cur_func_label = QLabel("None")

        cur_func_layout.addWidget(self.cur_func_label)
        cur_func_layout.addLayout(call_layout)
        call_layout.addWidget(self.incall_tree_view)
        call_layout.addWidget(self.outcall_tree_view)
        self.setLayout(cur_func_layout)

    def set_func_callers(self, cur_func, cur_std_item, depth=0):
        cur_func_callers = list(set(cur_func.callers))
        if depth <= self.func_depth:
            if cur_func_callers:
                for cur_func_caller in cur_func_callers:
                    new_std_item = StandardItem(cur_func_caller.name, 12)
                    cur_std_item.appendRow(new_std_item)
                    self.set_func_callers(cur_func_caller, new_std_item, depth + 1)

    def update_incoming_widget(self, cur_func):
        # Clear previous calls
        self.incall_tree_model.clear()
        self.incall_tree_model.setHorizontalHeaderLabels(["Incoming Calls"])
        incall_root_node = self.incall_tree_model.invisibleRootItem()

        cur_func_callers = list(set(cur_func.callers))
        root_std_items = []

        # Set root std Items
        if cur_func_callers:
            for cur_func_caller in cur_func_callers:
                root_std_items.append(StandardItem(cur_func_caller.name, 12))
                cur_std_item = root_std_items[-1]
                self.set_func_callers(cur_func_caller, cur_std_item)

        incall_root_node.appendRows(root_std_items)

    def set_func_callees(self, cur_func, cur_std_item, depth=0):
        cur_func_callees = list(set(cur_func.callees))
        if depth <= self.func_depth:
            if cur_func_callees:
                for cur_func_callee in cur_func_callees:
                    new_std_item = StandardItem(cur_func_callee.name, 12)
                    cur_std_item.appendRow(new_std_item)
                    self.set_func_callees(cur_func_callee, new_std_item, depth + 1)

    def update_outgoing_widget(self, cur_func):
        # Clear previous calls
        self.outcall_tree_model.clear()
        self.outcall_tree_model.setHorizontalHeaderLabels(["Outgoing Calls"])
        outcall_root_node = self.outcall_tree_model.invisibleRootItem()

        cur_func_callees = list(set(cur_func.callees))
        root_std_items = []

        # Set root std Items
        if cur_func_callees:
            for cur_func_callee in cur_func_callees:
                root_std_items.append(StandardItem(cur_func_callee.name, 12))
                cur_std_item = root_std_items[-1]
                self.set_func_callers(cur_func_callee, cur_std_item)

        outcall_root_node.appendRows(root_std_items)

    def notifyOffsetChanged(self, offset):
        cur_funcs = self.binary_view.get_functions_containing(offset)

        if not cur_funcs:
            self.cur_func_label.setText("None")
            self.incall_tree_model.clear()
            self.outcall_tree_model.clear()
            self.incall_tree_model.setHorizontalHeaderLabels(["Incoming Calls"])
            self.outcall_tree_model.setHorizontalHeaderLabels(["Outgoing Calls"])
        else:
            if cur_funcs[0].start != self.prev_func_offset:
                self.prev_func_offset = cur_funcs[0].start
                self.prev_func_offset = cur_funcs[0].start
                self.cur_func = cur_funcs[0]
                self.cur_func_label.setText(self.cur_func.name)
                self.update_incoming_widget(self.cur_func)
                self.update_outgoing_widget(self.cur_func)

    def shouldBeVisible(self, view_frame):
        if view_frame is None:
            return False
        else:
            return True

    def notifyViewChanged(self, view_frame):
        if view_frame is not None:
            self.view_frame = view_frame
            self.binary_view = self.view_frame.actionContext().binaryView

    def contextMenuEvent(self, event):
        self.m_contextMenuManager.show(self.m_menu, self.actionHandler)

    @staticmethod
    def create_widget(name, parent, data=None):
        return CallTreeWidget(parent, name)
        # return HelloDockWidget(parent, name)


def addStaticDockWidget():
    mw = QApplication.allWidgets()[0].window()
    dock_handler = mw.findChild(DockHandler, "__DockHandler")
    dock_widget = CallTreeWidget.create_widget("Call Tree", dock_handler.parent())
    dock_handler.addDockWidget(
        dock_widget, Qt.BottomDockWidgetArea, Qt.Horizontal, True
    )


addStaticDockWidget()
# addDynamicDockWidget()
