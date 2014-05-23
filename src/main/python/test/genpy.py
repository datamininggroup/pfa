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
  - let: {y: 0}
  - for: {x: 0}
    while: {"<": [x, 100]}
    step: {x: {+: [x, 1]}}
    do:
      - {set: {y: {+: [y, 1]}}}
  - {+: [input, y]}
options:
  timeout: 1000
''', debug=True)
        print engine.action(12)

if __name__ == "__main__":
    unittest.main()
