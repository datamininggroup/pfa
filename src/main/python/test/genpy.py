#!/usr/bin/env python

import json
import unittest

from pfa.reader import yamlToAst
from pfa.genpy import PFAEngine

class TestGeneratePython(unittest.TestCase):
    def testSimple(self):
        engine, = PFAEngine.fromYaml('''
name: test
input: {type: map, values: int}
output: int
action:
  - let: {counter: 1}
  - forkey: name
    forval: x
    in: input
    do:
      - set: {counter: {"*": [counter, x]}}
  - counter
options:
  timeout: 1000
''', debug=True)
        print engine.action({"one": 1, "two": 2, "three": 3, "four": 4, "five": 5})

if __name__ == "__main__":
    unittest.main()
