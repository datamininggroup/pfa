#!/usr/bin/env python

import json
import unittest

from pfa.reader import yamlToAst
from pfa.genpy import PFAEngine

class TestGeneratePython(unittest.TestCase):
    def testSimple(self):
        engine, = PFAEngine.fromYaml('''
name: test
input: [int, string]
output: int
action:
  - cast: input
    cases:
      - as: int
        named: x
        do: x
      - as: string
        named: x
        do: 5
fcns:
  plus:
    params: [{x: double}, {y: double}]
    ret: double
    do: {+: [x, y]}
options:
  timeout: 1000
''', debug=True)
        print engine.action({"int": 12})

if __name__ == "__main__":
    unittest.main()
