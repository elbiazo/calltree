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
    QLineEdit,
    QSpinBox,
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

from .calltree import CallTreeWidget
from binaryninja.settings import Settings

instance_id = 0
Settings().register_group("calltree", "Calltree")
Settings().register_setting(
    "calltree.depth",
    """
    {
        "title" : "Initial Function Depth",
        "type" : "number",
        "default" : 5,
        "description" : "Initial Function Depth",
        "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
    }
    """,
)
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

        # Create a QHBoxLayout instance
        call_layout = QVBoxLayout()
        # Add widgets to the layout
        func_depth = Settings().get_integer("calltree.depth")
        self.in_calltree = CallTreeWidget("Incoming Calls", func_depth)
        self.out_calltree = CallTreeWidget("Outgoing Calls", func_depth)

        cur_func_layout = QVBoxLayout()

        self.cur_func_label = QLabel("None")
        self.cur_func_label.setStyleSheet("font-weight: bold;")

        # Call function utilities
        self.in_expand_all_button = QPushButton("Expand")
        self.in_expand_all_button.clicked.connect(self.in_calltree.expand_all)
        self.out_expand_all_button = QPushButton("Expand")
        self.out_expand_all_button.clicked.connect(self.out_calltree.expand_all)

        self.in_func_filter = QLineEdit()
        self.out_func_filter = QLineEdit()
        self.in_func_filter.textChanged.connect(self.in_calltree.onTextChanged)
        self.out_func_filter.textChanged.connect(self.out_calltree.onTextChanged)

        in_util_layout = QHBoxLayout()
        out_util_layout = QHBoxLayout()

        self.in_spinbox = QSpinBox()
        self.out_spinbox = QSpinBox()
        self.in_spinbox.valueChanged.connect(self.in_spinbox_changed)
        self.out_spinbox.valueChanged.connect(self.out_spinbox_changed)

        in_util_layout.addWidget(self.in_func_filter)
        in_util_layout.addWidget(self.in_expand_all_button)
        in_util_layout.addWidget(self.in_spinbox)
        out_util_layout.addWidget(self.out_func_filter)
        out_util_layout.addWidget(self.out_expand_all_button)
        out_util_layout.addWidget(self.out_spinbox)
        self.in_spinbox.setValue(self.in_calltree.func_depth)
        self.out_spinbox.setValue(self.out_calltree.func_depth)

        cur_func_layout.addWidget(self.cur_func_label)
        cur_func_layout.addLayout(call_layout)

        call_layout.addWidget(self.in_calltree.get_treeview())
        call_layout.addLayout(in_util_layout)
        call_layout.addWidget(self.out_calltree.get_treeview())
        call_layout.addLayout(out_util_layout)

        self.setLayout(cur_func_layout)

    def in_spinbox_changed(self):
        self.in_calltree.func_depth = self.in_spinbox.value()
        if self.cur_func is not None:
            self.in_calltree.update_widget(self.cur_func, True)

    def out_spinbox_changed(self):
        self.out_calltree.func_depth = self.out_spinbox.value()
        if self.cur_func is not None:
            self.out_calltree.update_widget(self.cur_func, False)

    def notifyOffsetChanged(self, offset):
        cur_funcs = self.binary_view.get_functions_containing(offset)

        if not cur_funcs:
            self.prev_func_offset = None
            self.cur_func_label.setText("None")
            self.in_calltree.clear()
            self.out_calltree.clear()
        else:
            if cur_funcs[0].start != self.prev_func_offset:
                self.prev_func_offset = cur_funcs[0].start
                self.cur_func = cur_funcs[0]
                self.cur_func_label.setText(self.cur_func.name)
                self.in_calltree.update_widget(self.cur_func, True)
                self.out_calltree.update_widget(self.cur_func, False)

    def notifyViewChanged(self, view_frame):
        if view_frame is None:
            self.datatype.setText("None")
            self.data = None
        else:
            self.datatype.setText(view_frame.getCurrentView())
            view = view_frame.getCurrentViewInterface()
            self.data = view.getData()
            self.binary_view = view_frame.actionContext().binaryView
            self.in_calltree.binary_view = self.binary_view
            self.out_calltree.binary_view = self.binary_view

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
