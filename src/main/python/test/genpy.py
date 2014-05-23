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
  - cond:
      - if: false
        then: {set: {x: 100}}
      - if: false
        then: {set: {x: -100}}
      - if: false
        then: {set: {x: 100}}
  - {+: [input, x]}
''', debug=True)
        print engine.action(12)

if __name__ == "__main__":
    unittest.main()
