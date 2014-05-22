#!/usr/bin/env python

import json
import unittest

from pfa.reader import yamlToAst
from pfa.genpy import PFAEngine

class TestGeneratePython(unittest.TestCase):
    def testSimple(self):
        engine, = PFAEngine.fromYaml('''
name: test
input: double
output: double
action:
  - 3.14
''')
        print engine.action(99)

if __name__ == "__main__":
    unittest.main()
