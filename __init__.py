from binaryninja import log
from binaryninjaui import DockHandler, DockContextHandler, UIActionHandler
from PySide6 import QtCore
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QMainWindow, QTreeView, QHBoxLayout, QWidget, QHeaderView, QLabel, QVBoxLayout
from PySide6.QtGui import QFont, QColor, QStandardItemModel, QStandardItem

class StandardItem(QStandardItem):
    def __init__(self, txt='', font_size=12, set_bold=False, color=QColor(0, 0, 0)):
        super().__init__()

        fnt = QFont('Open Sans', font_size)
        fnt.setBold(set_bold)

        self.setEditable(False)
        # self.setForeground(color)
        self.setFont(fnt)
        self.setText(txt)



class CallTreeWidget(QWidget, DockContextHandler):
    def __init__(self, parent, name):
        QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)
        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)
        self.cur_offset = 0
        self.binary_view = None
        # self.resize(500, 700)
        # Create a QHBoxLayout instance
        layout = QHBoxLayout()
        # Add widgets to the layout
        self.incall_tree_view = QTreeView()
        outcall_tree_view = QTreeView()

        self.incall_tree_mode = QStandardItemModel()

        # first_callers_root = StandardItem('0x1c430', 16, True)
    
        # first_callers_1 = StandardItem('inFUNC_1', 16, True)
        # first_callers_1.setText(hex(self.cur_offset))
        # first_callers_root.appendRows([first_callers_1])

        # second_callers = StandardItem('inFUNC_2', 16, True)
        # incall_root_node.appendRow(self.first_callers_root)
        # incall_root_node.appendRow(second_callers)

        treeModel_2 = QStandardItemModel()
        treeModel_2.setHorizontalHeaderLabels(['Outgoing Calls'])
        outcall_root_node = treeModel_2.invisibleRootItem()

        first_callers_root_2 = StandardItem('outFUNC_1', 16, True)
        first_callers_1 = StandardItem('outFUNC_1', 16, True)
        first_callers_root_2.appendRows([first_callers_1])

        second_callers = StandardItem('outFUNC_2', 16, True)

        outcall_root_node.appendRow(first_callers_root_2)
        outcall_root_node.appendRow(second_callers)

        self.incall_tree_view.setModel(self.incall_tree_mode)
        self.incall_tree_view.expandAll()
        outcall_tree_view.setModel(treeModel_2)
        outcall_tree_view.expandAll()
        layout_2 = QVBoxLayout()
        self.cur_func = QLabel('None')

        layout_2.addWidget(self.cur_func)
        layout_2.addLayout(layout)
        layout.addWidget(self.incall_tree_view)
        layout.addWidget(outcall_tree_view)
        self.setLayout(layout_2)

    def update_incoming_widget(self, offset):
        pass



    def notifyOffsetChanged(self, offset):
        self.cur_offset = offset

        self.incall_tree_mode.clear()
        self.incall_tree_mode.setHorizontalHeaderLabels(['Incoming Calls'])
        incall_root_node = self.incall_tree_mode.invisibleRootItem()
        first_callers_root = StandardItem(self.binary_view.get_functions_containing(offset)[0].name, 16, True)
    
        first_callers_1 = StandardItem('inFUNC_1', 16, True)
        first_callers_1.setText(hex(self.cur_offset))
        first_callers_root.appendRows([first_callers_1])

        second_callers = StandardItem('inFUNC_2', 16, True)
        incall_root_node.appendRow(first_callers_root)
        incall_root_node.appendRow(second_callers)
        self.incall_tree_view.expandAll()
        self.cur_func.setText(self.binary_view.get_functions_containing(offset)[0].name)

    def shouldBeVisible(self, view_frame):
        if view_frame is None:
            return False
        else:
            return True

    def notifyViewChanged(self, view_frame):
        self.view_frame = view_frame
        self.binary_view = self.view_frame.actionContext().binaryView

    def contextMenuEvent(self, event):
        self.m_contextMenuManager.show(self.m_menu, self.actionHandler)

    @staticmethod
    def create_widget(name, parent, data = None):
        return CallTreeWidget(parent, name)
        # return HelloDockWidget(parent, name)

def addStaticDockWidget():
    mw = QApplication.allWidgets()[0].window()
    dock_handler = mw.findChild(DockHandler, '__DockHandler')
    dock_widget = CallTreeWidget.create_widget("Call Tree", dock_handler.parent())
    dock_handler.addDockWidget(dock_widget, Qt.BottomDockWidgetArea, Qt.Horizontal, True)


addStaticDockWidget()
# addDynamicDockWidget()