from pathlib import Path
from binaryninjaui import (
    UIActionHandler,
    SidebarWidget,
    SidebarWidgetType,
    Sidebar,
)
from PySide6.QtCore import Qt, QSize, QPoint
from PySide6.QtWidgets import (
    QLabel,
    QVBoxLayout,
    QTabWidget,
    QPushButton,
    QHBoxLayout,
)
from PySide6.QtGui import (
    QImage,
    QIcon,
    QPixmap,
    QPainter,
    QPen,
    QPolygon,
    QColor,
    QPalette,
)

from .calltree import CalltreeWidget
from binaryninja.settings import Settings
from .demangle import demangle_name

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
        "default" : 10,
        "description" : "Max length of string to display in pinned tabs",
        "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
    }
    """,
)


def _button_icon(kind: str, color: QColor, size: int = 16) -> QIcon:
    """Draw a small, theme-colored toolbar icon at runtime.

    Avoids shipping separate image assets and works regardless of the platform's
    icon theme. ``kind`` is either "pin" or "remove".
    """
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing, True)
    painter.setPen(QPen(color, 2))
    if kind == "pin":
        painter.setBrush(color)
        # A thumbtack: a domed head above a centered downward spike.
        painter.drawEllipse(3, 1, 10, 5)
        painter.drawPolygon(QPolygon([QPoint(6, 5), QPoint(10, 5), QPoint(8, 15)]))
    else:  # "remove": an X
        painter.drawLine(4, 4, size - 4, size - 4)
        painter.drawLine(size - 4, 4, 4, size - 4)
    painter.end()
    return QIcon(pixmap)


# Sidebar widgets must derive from SidebarWidget, not QWidget. SidebarWidget is a QWidget but
# provides callbacks for sidebar events, and must be created with a title.
class CalltreeSidebarWidget(SidebarWidget):
    def __init__(self, name: str, frame, data):
        SidebarWidget.__init__(self, name)
        self.datatype = QLabel("")
        self.data = data
        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)
        self.prev_location = None
        self.binary_view = None
        self.cur_func = None
        # Set by a tree's click handler to skip re-rooting the Current tab on the
        # next view-location change (see notifyViewLocationChanged).
        self.skip_next_update = False

        calltree_layout = QVBoxLayout()

        # Toolbar: pin the current tab / remove the active pinned tab.
        calltree_options = QHBoxLayout()
        btn_size = QSize(50, 25)
        icon_color = self.palette().color(QPalette.ButtonText)

        self.pin_tab_button = QPushButton()
        self.pin_tab_button.setIcon(_button_icon("pin", icon_color))
        self.pin_tab_button.setToolTip("Pin the current call tree in a new tab")
        self.pin_tab_button.setFixedSize(btn_size)
        self.pin_tab_button.clicked.connect(self.pin_current_tab)

        self.remove_current_tab_button = QPushButton()
        self.remove_current_tab_button.setIcon(_button_icon("remove", icon_color))
        self.remove_current_tab_button.setToolTip("Remove the active pinned tab")
        self.remove_current_tab_button.setFixedSize(btn_size)
        self.remove_current_tab_button.clicked.connect(self.remove_current_tab)

        calltree_options.addStretch()
        calltree_options.addWidget(self.pin_tab_button)
        calltree_options.addWidget(self.remove_current_tab_button)

        self.calltree_tab = QTabWidget()
        self.current_calltree = CalltreeWidget(sidebar=self)
        self.calltree_tab.addTab(self.current_calltree, "Current")
        # The Current tab is not refreshed while it is hidden (e.g. a pinned tab is
        # active), so refresh it when the user switches back to it to reflect any
        # navigation that happened meanwhile.
        self.calltree_tab.currentChanged.connect(self._on_tab_changed)

        calltree_layout.addLayout(calltree_options)
        calltree_layout.addWidget(self.calltree_tab)
        calltree_layout.setContentsMargins(0, 0, 0, 0)
        calltree_layout.setSpacing(0)
        self.setLayout(calltree_layout)

    def remove_current_tab(self):
        # never remove current tab
        cur_tab_index = self.calltree_tab.currentIndex()
        if cur_tab_index != 0:
            self.calltree_tab.removeTab(cur_tab_index)

    def pin_current_tab(self):
        if self.cur_func is not None:
            pinned_calltree = CalltreeWidget(sidebar=self)
            cur_func_name = self.current_calltree.cur_func_text.toPlainText()
            pinned_calltree.cur_func_text.setText(cur_func_name)

            # TODO: find a way to do deepcopy instead of updating widget everytime
            pinned_calltree.in_calltree.binary_view = self.binary_view
            pinned_calltree.out_calltree.binary_view = self.binary_view
            pinned_calltree.in_calltree.update_widget(self.cur_func, force=True)
            pinned_calltree.out_calltree.update_widget(self.cur_func, force=True)
            pinned_calltree.cur_func_layout.binary_view = self.binary_view

            max_pinned_name_len = Settings().get_integer("calltree.pin_name_len")
            self.calltree_tab.addTab(
                pinned_calltree, cur_func_name[:max_pinned_name_len]
            )

    def _refresh_current_tab(self):
        """Rebuild the Current tab's caller/callee trees for the latest function.

        While the Current tab is hidden its trees are not updated (see the
        visibility guard in ``CallTreeLayout.update_widget``), so refresh them when
        the tab becomes visible again to avoid showing a stale function.
        """
        if self.cur_func is not None:
            self.current_calltree.in_calltree.update_widget(self.cur_func, force=True)
            self.current_calltree.out_calltree.update_widget(self.cur_func, force=True)

    def _on_tab_changed(self, index):
        if index == 0:
            self._refresh_current_tab()

    def showEvent(self, event):
        super().showEvent(event)
        if self.calltree_tab.currentIndex() == 0:
            self._refresh_current_tab()

    def notifyViewLocationChanged(self, view, location):
        def extract_location_info(location):
            # make a copy of location values so that they are retained after
            # location object is freed
            return [
                location.getOffset(),
                location.getInstrIndex(),
                location.getFunction(),
            ]

        # A single click in a call tree navigates the main view to a call site but
        # must not touch the Current tab at all. The click handler sets
        # skip_next_update just before this fires, so consume it and return without
        # updating self.cur_func or re-rendering the Current tab. Keeping cur_func
        # untouched also keeps a later _refresh_current_tab() rooted on the same
        # function. prev_location is advanced so a follow-up same-address event
        # (different InstrIndex) doesn't re-root the Current tab either.
        if self.skip_next_update:
            self.skip_next_update = False
            self.prev_location = extract_location_info(location)
            return

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
        self.current_calltree.cur_func_layout.binary_view = self.binary_view


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
