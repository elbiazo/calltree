import binaryninja

# Graph-backed call-graph API, importable from the Binary Ninja Python console:
#     from calltree import get_call_graph
#     cg = get_call_graph(bv)
# Exposed regardless of the UI so it can be used headlessly.
from .callgraph import CallGraph, get_call_graph  # noqa: F401

if binaryninja.core_ui_enabled():
    from . import init

__all__ = ["CallGraph", "get_call_graph"]
