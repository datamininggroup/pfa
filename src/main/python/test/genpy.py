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
  - let: {x: 10}
  - let:
      y:
        if: false
        then: 100
        else: 1000000
  - {+: [input, y]}
''', debug=True)
        print engine.action(12)

if __name__ == "__main__":
    unittest.main()
