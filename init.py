import copy
from pathlib import Path
from binaryninjaui import (
    UIActionHandler,
    SidebarWidget,
    SidebarWidgetType,
    Sidebar,
)
from PySide6.QtCore import Qt, QSize
from PySide6.QtWidgets import (
    QLabel,
    QVBoxLayout,
    QScrollArea,
    QWidget,
    QTabWidget,
    QPushButton,
    QSpinBox,
    QHBoxLayout,
)
from PySide6.QtGui import QImage

from .calltree import CallTreeLayout, CurrentFunctionNameLayout, CurrentCalltreeWidget
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
Settings().register_setting(
    "calltree.pin_name_len",
    """
    {
        "title" : "Pinned Name Length",
        "type" : "number",
        "default" : 5,
        "description" : "Max length of string to display in pinned tabs",
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
        self.prev_location = None
        self.binary_view = None

        # Create a QHBoxLayout instance
        calltree_layout = QVBoxLayout()

        # calltree options
        calltree_options = QHBoxLayout()

        self.pin_tab_button = QPushButton("P")
        btn_size = QSize(25, 25)
        self.pin_tab_button.setFixedSize(btn_size)
        self.pin_tab_button.clicked.connect(self.pin_current_tab)
        self.remove_current_tab_button = QPushButton("R")
        btn_size = QSize(25, 25)
        self.remove_current_tab_button.setFixedSize(btn_size)
        self.remove_current_tab_button.clicked.connect(self.remove_current_tab)

        calltree_options.addStretch()
        calltree_options.addWidget(self.pin_tab_button)
        calltree_options.addWidget(self.remove_current_tab_button)

        # calltree tab
        self.calltree_tab = QTabWidget()
        self.current_calltree = CurrentCalltreeWidget()
        self.calltree_tab.addTab(self.current_calltree, "Current")

        calltree_layout.addLayout(calltree_options)
        calltree_layout.addWidget(self.calltree_tab)
        self.setLayout(calltree_layout)

    def remove_current_tab(self):
        # never remove current tab
        cur_tab_index = self.calltree_tab.currentIndex()
        if cur_tab_index != 0:
            self.calltree_tab.removeTab(cur_tab_index)

    def pin_current_tab(self):
        pinned_calltree = CurrentCalltreeWidget()
        cur_func_name = self.current_calltree.cur_func_text.toPlainText()
        pinned_calltree.cur_func_text.setText(cur_func_name)

        # TODO: find a way to do deepcopy instead of updating widget everytime
        pinned_calltree.in_calltree.binary_view = self.binary_view
        pinned_calltree.out_calltree.binary_view = self.binary_view
        pinned_calltree.in_calltree.update_widget(self.cur_func)
        pinned_calltree.out_calltree.update_widget(self.cur_func)

        max_pinned_name_len = Settings().get_integer("calltree.pin_name_len")
        self.calltree_tab.addTab(pinned_calltree, cur_func_name[:max_pinned_name_len])

    def notifyViewLocationChanged(self, view, location):
        def extract_location_info(location):
            # make a copy of location values so that they are retained after
            # location object is freed
            return [
                location.getOffset(),
                location.getInstrIndex(),
                location.getFunction(),
            ]

        self.cur_func = location.getFunction()
        if self.cur_func is None:
            self.prev_location = None
            self.current_calltree.cur_func_text.setText("None")
            self.current_calltree.in_calltree.clear()
            self.current_calltree.out_calltree.clear()
            return

        if self.prev_location:
            offset, index, *_ = self.prev_location
            if offset == location.getOffset() and index != location.getInstrIndex():
                # sometimes same address is called multiple times with different
                # InstrIndex. Update previous and do not take any further actions
                self.prev_location = extract_location_info(location)
                return

        skip_update = any(
            (
                self.current_calltree.in_calltree.skip_update,
                self.current_calltree.out_calltree.skip_update,
            )
        )

        # check if any treeview wants the update to be skipped
        if skip_update:
            # do not update, but reset it to false
            self.current_calltree.in_calltree.skip_update = False
            self.current_calltree.out_calltree.skip_update = False
        else:
            self.current_calltree.cur_func_text.setText(
                demangle_name(self.binary_view, self.cur_func.name)
            )
            self.current_calltree.in_calltree.update_widget(self.cur_func)
            self.current_calltree.out_calltree.update_widget(self.cur_func)

        self.prev_location = extract_location_info(location)

    def notifyViewChanged(self, view_frame):
        if view_frame is None:
            self.datatype.setText("None")
            self.data = None
            return

        new_binaryview = view_frame.actionContext().binaryView
        if self.binary_view == new_binaryview:
            return

        # only update if view has changed
        self.binary_view = new_binaryview
        self.datatype.setText(view_frame.getCurrentView())
        view = view_frame.getCurrentViewInterface()
        self.data = view.getData()
        self.current_calltree.in_calltree.binary_view = self.binary_view
        self.current_calltree.out_calltree.binary_view = self.binary_view

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
