from binaryninjaui import (
    DockHandler,
    DockContextHandler,
    UIActionHandler,
    SidebarWidget,
    SidebarWidgetType,
    Sidebar,
)
from binaryninja import log_info
from PySide6.QtCore import Qt, QRectF
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
)


instance_id = 0


class BNFuncItem(QStandardItem):
    def __init__(self, func_name):
        super().__init__()
        self.setText(func_name)


# Sidebar widgets must derive from SidebarWidget, not QWidget. SidebarWidget is a QWidget but
# provides callbacks for sidebar events, and must be created with a title.
class CalltreeSidebarWidget(SidebarWidget):
    def __init__(self, name, frame, data):
        global instance_id
        SidebarWidget.__init__(self, name)
        self.datatype = QLabel("")
        self.data = data
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
        self.outcall_tree_view.doubleClicked.connect(self.out_goto_func)
        self.incall_tree_view.doubleClicked.connect(self.in_goto_func)
        cur_func_layout = QVBoxLayout()
        self.cur_func_label = QLabel("None")
        self.cur_func_label.setStyleSheet("font-weight: bold;")
        self.expand_all_button = QPushButton("Expand All")
        self.expand_all_button.clicked.connect(self.expand_all)

        cur_func_layout.addWidget(self.cur_func_label)
        cur_func_layout.addWidget(self.expand_all_button)
        cur_func_layout.addLayout(call_layout)
        call_layout.addWidget(self.outcall_tree_view)
        call_layout.addWidget(self.incall_tree_view)
        self.setLayout(cur_func_layout)

    def expand_all(self):
        self.incall_tree_view.expandAll()
        self.outcall_tree_view.expandAll()

    def out_goto_func(self, index):
        cur_item_index = self.outcall_tree_view.selectedIndexes()[0]
        cur_func = cur_item_index.model().itemFromIndex(index).func
        self.binary_view.navigate(self.binary_view.view, cur_func.start)

    def in_goto_func(self, index):
        cur_item_index = self.incall_tree_view.selectedIndexes()[0]
        cur_func = cur_item_index.model().itemFromIndex(index).func
        self.binary_view.navigate(self.binary_view.view, cur_func.start)

    def set_func_callers(self, cur_func, cur_std_item, depth=0):
        cur_func_callers = list(set(cur_func.callers))
        if depth <= self.func_depth:
            if cur_func_callers:
                for cur_func_caller in cur_func_callers:
                    new_std_item = BNFuncItem(cur_func_caller.name)
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
                root_std_items.append(BNFuncItem(cur_func_caller.name))
                cur_std_item = root_std_items[-1]
                self.set_func_callers(cur_func_caller, cur_std_item)

        incall_root_node.appendRows(root_std_items)

    def set_func_callees(self, cur_func, cur_std_item, depth=0):
        cur_func_callees = list(set(cur_func.callees))
        if depth <= self.func_depth:
            if cur_func_callees:
                for cur_func_callee in cur_func_callees:
                    new_std_item = BNFuncItem(cur_func_callee.name)
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
                root_std_items.append(BNFuncItem(cur_func_callee.name))
                cur_std_item = root_std_items[-1]
                self.set_func_callees(cur_func_callee, cur_std_item)

        outcall_root_node.appendRows(root_std_items)

    def notifyOffsetChanged(self, offset):
        cur_funcs = self.binary_view.get_functions_containing(offset)

        if not cur_funcs:
            self.prev_func_offset = None
            self.cur_func_label.setText("None")
            self.incall_tree_model.clear()
            self.outcall_tree_model.clear()
            self.incall_tree_model.setHorizontalHeaderLabels(["Incoming Calls"])
            self.outcall_tree_model.setHorizontalHeaderLabels(["Outgoing Calls"])
        else:
            if cur_funcs[0].start != self.prev_func_offset:
                self.prev_func_offset = cur_funcs[0].start
                self.cur_func = cur_funcs[0]
                self.cur_func_label.setText(self.cur_func.name)
                self.update_incoming_widget(self.cur_func)
                self.update_outgoing_widget(self.cur_func)

    def notifyViewChanged(self, view_frame):
        if view_frame is None:
            self.datatype.setText("None")
            self.data = None
        else:
            self.datatype.setText(view_frame.getCurrentView())
            view = view_frame.getCurrentViewInterface()
            self.data = view.getData()
            self.binary_view = view_frame.actionContext().binaryView

    def contextMenuEvent(self, event):
        self.m_contextMenuManager.show(self.m_menu, self.actionHandler)


class CalltreeSidebarWidgetType(SidebarWidgetType):
    def __init__(self):
        # Sidebar icons are 28x28 points. Should be at least 56x56 pixels for
        # HiDPI display compatibility. They will be automatically made theme
        # aware, so you need only provide a grayscale image, where white is
        # the color of the shape.
        icon = QImage(56, 56, QImage.Format_RGB32)
        icon.fill(0)

        # Render an "C" as the example icon
        p = QPainter()
        p.begin(icon)
        p.setFont(QFont("Open Sans", 56))
        p.setPen(QColor(255, 255, 255, 255))
        p.drawText(QRectF(0, 0, 56, 56), Qt.AlignCenter, "C")
        p.end()

        SidebarWidgetType.__init__(self, icon, "Calltree")

    def createWidget(self, frame, data):
        # This callback is called when a widget needs to be created for a given context. Different
        # widgets are created for each unique BinaryView. They are created on demand when the sidebar
        # widget is visible and the BinaryView becomes active.
        return CalltreeSidebarWidget("Calltree", frame, data)


# Register the sidebar widget type with Binary Ninja. This will make it appear as an icon in the
# sidebar and the `createWidget` method will be called when a widget is required.
Sidebar.addSidebarWidgetType(CalltreeSidebarWidgetType())
