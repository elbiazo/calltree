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
    QTabWidget,
)
from PySide6.QtGui import QImage

from .calltree import CalltreeWidget
from binaryninja.settings import Settings
from binaryninja import (
    execute_on_main_thread,
    BinaryDataNotification,
    NotificationType,
)
from .demangle import demangle_name
from .callgraph import get_call_graph, peek_call_graph
from binaryninja.flowgraph import FlowGraph, FlowGraphNode
from binaryninja.enums import BranchType, InstructionTextTokenType, HighlightStandardColor
from binaryninja.function import DisassemblyTextLine, InstructionTextToken

Settings().register_group("calltree", "Calltree")
Settings().register_setting(
    "calltree.in_depth",
    """
    {
        "title" : "Initial Function Incoming Depth",
        "type" : "number",
        "default" : 10,
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
        "default" : 10,
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
Settings().register_setting(
    "calltree.max_nodes",
    """
    {
        "title" : "Max Auto-Expand Nodes (BFS)",
        "type" : "number",
        "default" : 3000,
        "minValue" : 10,
        "maxValue" : 1000000,
        "description" : "Safety cap on how many rows the tree auto-expands (breadth-first) when navigating. Lower it if deep navigation feels slow; raise it to reveal more before expanding manually.",
        "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
    }
    """,
)


def _widget_alive(widget) -> bool:
    """True if the Qt C++ object behind ``widget`` still exists.

    Deferred callbacks (e.g. analysis-completion events hopped to the main thread) can
    fire after Binary Ninja has torn the sidebar down, leaving the Python wrapper
    pointing at a freed C++ object. Callers still guard the actual Qt access, but this
    lets them bail early and skip wasted work / re-arming."""
    try:
        import shiboken6

        return shiboken6.isValid(widget)
    except Exception:
        return True  # can't tell -> assume alive; the Qt access is still guarded


class _CalltreeFunctionNotification(BinaryDataNotification):
    """Flags changed functions dirty in the cached CallGraph so only those are
    rebuilt (instead of wiping the whole graph).

    Callbacks may run on analysis worker threads, so they only record addresses;
    the graph itself is mutated later on the main thread via CallGraph.apply_dirty()
    (invoked from expand / after analysis completion).
    """

    def __init__(self, bv):
        super().__init__(NotificationType.FunctionUpdates)
        self._bv = bv

    def _mark(self, func):
        cg = peek_call_graph(self._bv)
        if cg is not None:
            try:
                cg.mark_dirty(func.start)
            except Exception:
                pass

    def function_updated(self, view, func):
        self._mark(func)

    def function_added(self, view, func):
        self._mark(func)

    def function_removed(self, view, func):
        self._mark(func)


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
        # Per-view analysis notification that flags dirty functions (see below).
        self._notification = None
        # Set by a tree's click handler to skip re-rooting the Current tab on the
        # next view-location change (see notifyViewLocationChanged).
        self.skip_next_update = False

        calltree_layout = QVBoxLayout()

        self.calltree_tab = QTabWidget()
        # Make the "Current" / pinned tabs a bit bigger via a larger tab-bar font. A
        # QSS `padding` rule would force Qt into stylesheet (non-native) tab rendering,
        # which drew a stray border/white line and squared-off corners; bumping the font
        # keeps native rendering while enlarging the tabs.
        _tab_bar = self.calltree_tab.tabBar()
        _tab_font = _tab_bar.font()
        if _tab_font.pointSizeF() > 0:
            _tab_font.setPointSizeF(_tab_font.pointSizeF() * 1.15)
            _tab_bar.setFont(_tab_font)
        self.current_calltree = CalltreeWidget(sidebar=self)
        self.calltree_tab.addTab(self.current_calltree, "Current")
        # The Current tab is not refreshed while it is hidden (e.g. a pinned tab is
        # active), so refresh it when the user switches back to it to reflect any
        # navigation that happened meanwhile.
        self.calltree_tab.currentChanged.connect(self._on_tab_changed)

        calltree_layout.addWidget(self.calltree_tab)
        calltree_layout.setContentsMargins(0, 0, 0, 0)
        calltree_layout.setSpacing(0)
        self.setLayout(calltree_layout)

    def remove_current_tab(self):
        # never remove current tab
        cur_tab_index = self.calltree_tab.currentIndex()
        if cur_tab_index != 0:
            self.calltree_tab.removeTab(cur_tab_index)

    def create_call_graph(self):
        """Open a Binary Ninja FlowGraph of every function currently shown in the
        active tab's incoming + outgoing trees, wired by their call relationships.

        Nodes are color-coded (root / incoming caller / outgoing callee) and clickable:
        each node carries a code-symbol token at the function's address, so
        double-clicking it navigates the view there."""
        bv = self.binary_view
        widget = self.calltree_tab.currentWidget()
        if bv is None or widget is None:
            return

        root_func = widget.in_calltree.cur_func
        in_edges = widget.in_calltree.collect_edges()
        out_edges = widget.out_calltree.collect_edges()

        # Gather nodes + categorize each function: root wins, else incoming vs outgoing
        # (a function in both, e.g. via a cycle, keeps its first-seen incoming tag).
        edge_set = set()
        funcs = {}
        category = {}
        for edges, cat in ((in_edges, "in"), (out_edges, "out")):
            for caller, callee in edges:
                edge_set.add((caller.start, callee.start))
                for f in (caller, callee):
                    funcs.setdefault(f.start, f)
                    category.setdefault(f.start, cat)
        if root_func is not None:  # include the root even if isolated
            funcs.setdefault(root_func.start, root_func)
            category[root_func.start] = "root"

        if not funcs:
            return

        names = {
            addr: demangle_name(bv, f.name) or f.name or f"sub_{addr:x}"
            for addr, f in funcs.items()
        }

        colors = {
            "root": HighlightStandardColor.OrangeHighlightColor,
            "in": HighlightStandardColor.BlueHighlightColor,
            "out": HighlightStandardColor.GreenHighlightColor,
        }

        graph = FlowGraph()
        nodes = {}
        for addr, func in funcs.items():
            node = FlowGraphNode(graph)
            # A code-symbol token carrying the address makes the node navigable
            # (double-click jumps the view to the function).
            token = InstructionTextToken(
                InstructionTextTokenType.CodeSymbolToken, names[addr], addr
            )
            node.lines = [DisassemblyTextLine([token], addr)]
            node.highlight = colors[category.get(addr, "out")]
            graph.append(node)
            nodes[addr] = node
        for caller_addr, callee_addr in edge_set:
            nodes[caller_addr].add_outgoing_edge(
                BranchType.UnconditionalBranch, nodes[callee_addr]
            )

        title = "Calltree"
        if root_func is not None:
            title = f"Calltree: {demangle_name(bv, root_func.name) or root_func.name}"
        bv.show_graph_report(title, graph)

    def pin_current_tab(self):
        if self.cur_func is not None:
            pinned_calltree = CalltreeWidget(sidebar=self)
            cur_func_name = self.current_calltree.cur_func_text.text()
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

    def set_current_function(self, func):
        """Re-root the Current tab onto ``func`` (label + caller/callee trees).

        When the Current tab is hidden the trees are rebuilt lazily by
        _refresh_current_tab on the next show; the label is always updated.
        """
        self.cur_func = func
        self.current_calltree.cur_func_text.setText(
            demangle_name(self.binary_view, func.name)
        )
        self.current_calltree.in_calltree.update_widget(func)
        self.current_calltree.out_calltree.update_widget(func)

    def notifyViewLocationChanged(self, view, location):
        def extract_location_info(location):
            # make a copy of location values so that they are retained after
            # location object is freed
            return [
                location.getOffset(),
                location.getInstrIndex(),
                location.getFunction(),
            ]

        # A single click in a call tree (or the function-name header) navigates the
        # main view but must not touch the Current tab at all. The click handler
        # sets skip_next_update just before this fires, so consume it and return
        # without updating self.cur_func or re-rendering the Current tab. Keeping
        # cur_func untouched also keeps a later _refresh_current_tab() rooted on the
        # same function. prev_location is advanced so a follow-up same-address event
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

        self.set_current_function(self.cur_func)
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
        old_binaryview = self.binary_view
        self.binary_view = new_binaryview
        self.datatype.setText(view_frame.getCurrentView())
        view = view_frame.getCurrentViewInterface()
        self.data = view.getData()
        self.current_calltree.in_calltree.binary_view = self.binary_view
        self.current_calltree.out_calltree.binary_view = self.binary_view
        self.current_calltree.cur_func_layout.binary_view = self.binary_view
        self._register_notification(old_binaryview, new_binaryview)
        self._arm_analysis_event(self.binary_view)

    def _register_notification(self, old_bv, new_bv):
        """Move the dirty-tracking notification from the old view to the new one."""
        if self._notification is not None and old_bv is not None:
            try:
                old_bv.unregister_notification(self._notification)
            except Exception:
                pass
        self._notification = None
        if new_bv is None:
            return
        try:
            self._notification = _CalltreeFunctionNotification(new_bv)
            new_bv.register_notification(self._notification)
        except Exception:
            self._notification = None

    def _arm_analysis_event(self, bv):
        """(Re)register a one-shot analysis-completion callback for ``bv``.

        Binary Ninja runs the callback once per analysis pass, so we re-arm after
        each refresh. This keeps the call trees correct as analysis discovers more
        calls -- most visibly right after a file is first opened, when the initial
        tree can be built before analysis has found every callee.
        """
        if bv is None:
            return
        try:
            bv.add_analysis_completion_event(lambda: self._on_analysis_complete(bv))
        except Exception:
            pass

    def _on_analysis_complete(self, bv):
        # Fires on an analysis worker thread; hop to the UI thread before touching
        # the graph cache or Qt models.
        execute_on_main_thread(lambda: self._refresh_after_analysis(bv))

    def _refresh_after_analysis(self, bv):
        # This deferred callback can fire after the sidebar widget has been destroyed
        # (view/tab closed). Bail if our C++ widget is gone so we don't touch freed Qt
        # objects, and don't re-arm — otherwise the completion event keeps firing.
        if not _widget_alive(self) or self.binary_view is not bv:
            return  # different view active now, or widget gone: ignore this completion
        try:
            cg = get_call_graph(bv)
        except ImportError:
            return  # networkx missing -> trees stay empty, nothing to refresh
        # Rebuild functions flagged dirty by the notification plus the current root
        # (whose direct calls may only be discovered as analysis finishes), then
        # re-render — without wiping the whole graph.
        if self.cur_func is not None:
            cg.mark_dirty(self.cur_func.start)
        cg.apply_dirty()
        try:
            if self.cur_func is not None:
                self.set_current_function(self.cur_func)
        except RuntimeError:
            return  # widget destroyed after the alive-check; stop and don't re-arm
        self._arm_analysis_event(bv)


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
