#!/usr/bin/env python3
"""Demangling regression tests; run directly without Binary Ninja installed."""

import importlib.util
import os
import sys
import unittest
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock, patch


_HERE = os.path.dirname(os.path.abspath(__file__))
_DEMANGLE_PY = os.path.normpath(os.path.join(_HERE, "..", "..", "demangle.py"))


class DemangleTests(unittest.TestCase):
    def setUp(self):
        self.bv = SimpleNamespace(arch=object())
        self.binaryninja = ModuleType("binaryninja")
        self.binaryninja.demangle_ms = Mock(return_value=(None, "plain_function"))
        self.binaryninja.demangle_gnu3 = Mock(return_value=(None, "plain_function"))

        spec = importlib.util.spec_from_file_location("calltree_demangle", _DEMANGLE_PY)
        module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {"binaryninja": self.binaryninja}):
            spec.loader.exec_module(module)
        self.demangle_name = module.demangle_name

    def test_microsoft_demangling_preserves_scopes(self):
        name = "?run@Widget@ns@@QEAAXXZ"
        self.binaryninja.demangle_ms.return_value = (object(), ["ns", "Widget", "run"])

        self.assertEqual(self.demangle_name(self.bv, name), "ns::Widget::run")
        self.binaryninja.demangle_ms.assert_called_once_with(self.bv.arch, name)

    def test_gnu_demangling_preserves_scopes(self):
        name = "_ZN2ns6Widget3runEv"
        self.binaryninja.demangle_gnu3.return_value = (object(), ["ns", "Widget", "run"])

        self.assertEqual(self.demangle_name(self.bv, name), "ns::Widget::run")
        self.binaryninja.demangle_gnu3.assert_called_once_with(self.bv.arch, name)

    def test_unmangled_name_is_unchanged(self):
        self.assertEqual(self.demangle_name(self.bv, "plain_function"), "plain_function")


if __name__ == "__main__":
    unittest.main()
