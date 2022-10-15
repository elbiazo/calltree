from enum import Enum
from binaryninja import FlowGraph, FlowGraphNode, EdgeStyle, EdgePenStyle, ThemeColor, BranchType, show_graph_report
import copy

class CallSite(Enum):
    CALLER = 0
    CALLEE = 1

class CallGraph:
    def __init__(self, bv):
        self.bv = bv

        # Graph will be generic dict graph
        self.graph = {}
        self.graph[CallSite.CALLER] = {}
        self.graph[CallSite.CALLEE] = {}

    def _add(self, func, callsite: CallSite):
        """
        Adds current function and its node to graph
        it will return node's children
        """
        callsites = []
        callsites = self.graph[callsite].get(func)
        # If callsite isnt in graph get it
        if callsites is None:
            if callsite is CallSite.CALLER:
                callers = list(set(func.callers))
                print(f'{func}: {func.callers}')
                self.graph[callsite][func] = callers
                callsites = callers
            elif callsite is CallSite.CALLEE:
                callees = list(set(func.callees))
                self.graph[callsite][func] = callees
                callsites = callees


        return list(callsites)


    def update(self, addr: int, depth: int, callsite: CallSite):
        """
        Add graph
        """
        func = self.bv.get_function_at(addr)

        if func:
            depth = 5
            cur_funcs = [func]
            for _ in range(depth):
                while len(cur_funcs):
                    cur_func = cur_funcs.pop()
                    cur_children = self._add(cur_func, callsite)
                    if cur_children:
                        cur_funcs.extend(cur_children)

                        # check if there is recursion by looking at if there are cur_func in cur_children. If there is you have to remove it so that it
                        # don't hit infinite recursion
                        if cur_func in cur_children:
                            cur_funcs.remove(cur_func)
    

    def print(self, cur_func, callsite: CallSite):
        if cur_func in self.graph[callsite]:
            while True:
                if cur_func is None:
                    break
                print(cur_func)
                print(self.graph[callsite].get(cur_func))
                break

                
            


