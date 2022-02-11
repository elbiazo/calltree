from pathlib import Path
from binaryninjaui import (
    UIActionHandler,
    SidebarWidget,
    SidebarWidgetType,
    Sidebar,
)

from PySide6.QtWidgets import (
    QLabel,
    QVBoxLayout,
)
from PySide6.QtGui import QImage

from .calltree import CallTreeLayout
from binaryninja.settings import Settings

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
        call_layout = QVBoxLayout()
        # Add widgets to the layout
        in_func_depth = Settings().get_integer("calltree.in_depth")
        out_func_depth = Settings().get_integer("calltree.out_depth")

        self.in_calltree = CallTreeLayout("Incoming Calls", in_func_depth, True)
        self.out_calltree = CallTreeLayout("Outgoing Calls", out_func_depth, False)

        cur_func_layout = QVBoxLayout()

        self.cur_func_label = QLabel("None")
        self.cur_func_label.setStyleSheet("font-weight: bold;")

        cur_func_layout.addWidget(self.cur_func_label)
        cur_func_layout.addLayout(call_layout)

        call_layout.addLayout(self.in_calltree)
        call_layout.addLayout(self.out_calltree)

        self.setLayout(cur_func_layout)

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
                cur_func = cur_funcs[0]
                self.cur_func_label.setText(cur_func.name)
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
