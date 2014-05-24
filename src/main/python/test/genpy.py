#!/usr/bin/env python

import json
import unittest

from pfa.reader import yamlToAst
from pfa.genpy import PFAEngine
from pfa.errors import PFAUserException

class TestGeneratePython(unittest.TestCase):
    def testSimple(self):
        engine, = PFAEngine.fromYaml('''
name: test
input: int
output: int
cells:
  stuff:
    init: 0
    type: int
    rollback: true
action:
  - cell: stuff
    to:
      params: [{x: int}]
      ret: int
      do: {+: [x, 1]}
  - if: {"<": [input, 5]}
    then: {error: "whatever"}
  - cell: stuff
''', debug=True)

        for x in xrange(10):
            try:
                print engine.action(x)
            except PFAUserException:
                pass

if __name__ == "__main__":
    unittest.main()
