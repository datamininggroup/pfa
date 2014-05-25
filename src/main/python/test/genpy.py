#!/usr/bin/env python

import json
import unittest

from pfa.reader import yamlToAst
from pfa.genpy import PFAEngine
from pfa.errors import PFAUserException

class TestGeneratePython(unittest.TestCase):
    def testLiteralNull(self):
        engine, = PFAEngine.fromYaml('''
input: "null"
output: "null"
action: null
''')
        self.assertEqual(engine.action(None), None)

    def testLiteralBoolean(self):
        engine, = PFAEngine.fromYaml('''
input: "null"
output: boolean
action: true
''')
        self.assertEqual(engine.action(None), True)

        engine, = PFAEngine.fromYaml('''
input: "null"
output: boolean
action: false
''')
        self.assertEqual(engine.action(None), False)

    def testLiteralInt(self):
        engine, = PFAEngine.fromYaml('''
input: "null"
output: int
action: 12
''')
        self.assertEqual(engine.action(None), 12)
        self.assertIsInstance(engine.action(None), int)

    def testLiteralLong(self):
        engine, = PFAEngine.fromYaml('''
input: "null"
output: long
action: {long: 12}
''')
        self.assertEqual(engine.action(None), 12)
        self.assertIsInstance(engine.action(None), int)

    def testLiteralFloat(self):
        engine, = PFAEngine.fromYaml('''
input: "null"
output: float
action: {float: 12}
''')
        self.assertEqual(engine.action(None), 12.0)
        self.assertIsInstance(engine.action(None), float)

    def testLiteralDouble(self):
        engine, = PFAEngine.fromYaml('''
input: "null"
output: double
action: 12.4
''')
        self.assertEqual(engine.action(None), 12.4)
        self.assertIsInstance(engine.action(None), float)

    def testLiteralString(self):
        engine, = PFAEngine.fromYaml('''
input: "null"
output: string
action: [["hello world"]]
''')
        self.assertEqual(engine.action(None), "hello world")
        self.assertIsInstance(engine.action(None), basestring)

        engine, = PFAEngine.fromYaml('''
input: "null"
output: string
action: {string: "hello world"}
''')
        self.assertEqual(engine.action(None), "hello world")
        self.assertIsInstance(engine.action(None), basestring)

    def testLiteralBase64(self):
        engine, = PFAEngine.fromYaml('''
input: "null"
output: bytes
action: {base64: "aGVsbG8="}
''')
        self.assertEqual(engine.action(None), "hello")
        self.assertIsInstance(engine.action(None), basestring)

    def testComplexLiterals(self):
        engine, = PFAEngine.fromYaml('''
input: "null"
output: bytes
action: {base64: "aGVsbG8="}
''')
        self.assertEqual(engine.action(None), "hello")
        self.assertIsInstance(engine.action(None), basestring)

if __name__ == "__main__":
    unittest.main()
