#!/usr/bin/env python

import json
import unittest

from pfa.reader import yamlToAst
from pfa.genpy import PFAEngine

class TestGeneratePython(unittest.TestCase):
    def testSimple(self):
        engine, = PFAEngine.fromYaml('''
name: test
input: int
output: double
action:
  - {u-: [input]}
''')
        print engine.action(12)

if __name__ == "__main__":
    unittest.main()
