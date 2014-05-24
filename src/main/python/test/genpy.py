#!/usr/bin/env python

import json
import unittest

from pfa.reader import yamlToAst
from pfa.genpy import PFAEngine

class TestGeneratePython(unittest.TestCase):
    def testSimple(self):
        engine, = PFAEngine.fromYaml('''
name: test
input: [double, string]
output: double
cells:
  stuff:
    init: 999
    type: int
action:
  - {cell: stuff, to: 123}
  - log: [["hey there"], 3.14, 5]
  - cast: input
    cases:
      - as: double
        named: x
        do: x
      - as: string
        named: x
        do: {cell: stuff}
fcns:
  plus:
    params: [{x: double}, {y: double}]
    ret: double
    do: {+: [x, y]}
options:
  timeout: 1000
''', debug=True)
        print engine.action({"string": "hey"})

if __name__ == "__main__":
    unittest.main()
