#!/usr/bin/env python

import json
import unittest

from pfa.reader import yamlToAst
from pfa.genpy import PFAEngine

class TestGeneratePython(unittest.TestCase):
    def testSimple(self):
        engine, = PFAEngine.fromYaml('''
name: test
input: "null"
output: R
action:
  - let:
      stuff: {type: {type: record, name: R, fields: [{name: one, type: int}, {name: two, type: double}, {name: three, type: string}]}, new: {"one": 1, "two": 2.0, "three": ["THREE"]}}
  - attr: stuff
    path: [[two]]
    to: 999
options:
  timeout: 1000
''', debug=True)
        print engine.action(None)

if __name__ == "__main__":
    unittest.main()
