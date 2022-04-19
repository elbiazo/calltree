from pathlib import Path
from binaryninjaui import (
    UIActionHandler,
    SidebarWidget,
    SidebarWidgetType,
    Sidebar,
)
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QVBoxLayout, QScrollArea, QWidget
from PySide6.QtGui import QImage

from .calltree import CallTreeLayout, CurrentFunctionLayout
from binaryninja.settings import Settings
from .demangle import demangle_name
instance_id = 0
Settings().register_group("calltree", "Calltree")
Settings().register_setting(
    "calltree.in_depth",
    """
    {
        "title" : "Initial Function Incoming Depth",
        "type" : "number",
        "default" : 5,
        "description" : "Initial Function Incoming Depth",
        "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
    }
    """,
)
Settings().register_setting(
    "calltree.out_depth",
    """
    {
        "title" : "Initial Function Outgoing Depth",
        "type" : "number",
        "default" : 5,
        "description" : "Initial Function Outgoing Depth",
        "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
    }
    """,
)


class ScrollLabel(QScrollArea):

    # constructor
    def __init__(self, *args, **kwargs):
        QScrollArea.__init__(self, *args, **kwargs)

        # making widget resizable
        self.setWidgetResizable(True)

        # making qwidget object
        content = QWidget(self)
        self.setWidget(content)

        # vertical box layout
        lay = QVBoxLayout(content)

        # creating label
        self.label = QLabel(content)
        self.label.setStyleSheet("font-weight: bold;")

        # setting alignment to the text
        self.label.setAlignment(Qt.AlignLeft | Qt.AlignTop)

        # adding label to the layout
        lay.addWidget(self.label)

    # the setText method
    def setText(self, text):
        # setting text to the label
        self.label.setText(text)

    # getting text method
    def text(self):

        # getting text of the label
        get_text = self.label.text()

        # return the text
        return get_text


# Sidebar widgets must derive from SidebarWidget, not QWidget. SidebarWidget is a QWidget but
# provides callbacks for sidebar events, and must be created with a title.
class CalltreeSidebarWidget(SidebarWidget):
    def __init__(self, name: str, frame, data):
        global instance_id
        SidebarWidget.__init__(self, name)
        self.datatype = QLabel("")
        self.data = data
        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)
        self.prev_func_offset = None
        self.binary_view = None

        # Create a QHBoxLayout instance
        calltree_layout = QVBoxLayout()
        # Add widgets to the layout
        in_func_depth = Settings().get_integer("calltree.in_depth")
        out_func_depth = Settings().get_integer("calltree.out_depth")

        self.in_calltree = CallTreeLayout("Incoming Calls", in_func_depth, True)
        self.out_calltree = CallTreeLayout("Outgoing Calls", out_func_depth, False)

        cur_func_layout = CurrentFunctionLayout()

        self.cur_func_text = cur_func_layout.cur_func_text

        calltree_layout.addLayout(cur_func_layout)
        calltree_layout.addLayout(self.in_calltree)
        calltree_layout.addLayout(self.out_calltree)

        self.setLayout(calltree_layout)

    def notifyOffsetChanged(self, offset):
        cur_funcs = self.binary_view.get_functions_containing(offset)

        if not cur_funcs:
            self.prev_func_offset = None
            self.cur_func_text.setText("None")
            self.in_calltree.clear()
            self.out_calltree.clear()
        else:
            if cur_funcs[0].start != self.prev_func_offset:
                self.prev_func_offset = cur_funcs[0].start
                cur_func = cur_funcs[0]
                self.cur_func_text.setText(demangle_name(self.binary_view, cur_func.name))
                self.in_calltree.cur_func = cur_func
                self.out_calltree.cur_func = cur_func
                self.in_calltree.update_widget(cur_func)
                self.out_calltree.update_widget(cur_func)

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

        root = Path(__file__).parent
        # Tree icons created by Ardiansyah - Flaticon
        icon = QImage(str(root.joinpath("icon.png")))

        SidebarWidgetType.__init__(self, icon, "Calltree")

    def createWidget(self, frame, data):
        # This callback is called when a widget needs to be created for a given context. Different
        # widgets are created for each unique BinaryView. They are created on demand when the sidebar
        # widget is visible and the BinaryView becomes active.
        return CalltreeSidebarWidget("Calltree", frame, data)


# Register the sidebar widget type with Binary Ninja. This will make it appear as an icon in the
# sidebar and the `createWidget` method will be called when a widget is required.
Sidebar.addSidebarWidgetType(CalltreeSidebarWidgetType())
