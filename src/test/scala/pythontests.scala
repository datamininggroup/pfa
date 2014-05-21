package test.scala.pythontest

import org.junit.runner.RunWith

import org.scalatest.FlatSpec
import org.scalatest.junit.JUnitRunner
import org.scalatest.Matchers

import org.python.core.Py
import org.python.core.PyString
import org.python.util.PythonInterpreter

import test.scala._

@RunWith(classOf[JUnitRunner])
class PythonTestSuite extends FlatSpec with Matchers {
  lazy val interpreter = {
    val sys = Py.getSystemState
    sys.path.append(new PyString("__pyclasspath__/python"))
    val interpreter = new PythonInterpreter
    interpreter.exec("import unittest")
    interpreter
  }

  def run(moduleName: String, className: String, verbosity: Int): Boolean = {
    interpreter.exec("import " + moduleName)
    interpreter.exec("suite = unittest.TestLoader().loadTestsFromTestCase(%s.%s)".format(moduleName, className))
    val result = interpreter.eval("unittest.TextTestRunner(verbosity=%d).run(suite)".format(verbosity))
    val booleanResult = result.__getattr__(new PyString("wasSuccessful")).__call__()
    booleanResult == Py.True
  }

  "Python tests" must "TestAstToJson" taggedAs(PythonTest) in {
    run("test.asttojson", "TestAstToJson", 2) should be (true)
  }

  it must "TestDataType" taggedAs(PythonTest) in {
    run("test.datatype", "TestDataType", 2) should be (true)
  }

  it must "TestJsonToAst" taggedAs(PythonTest) in {
    run("test.jsontoast", "TestJsonToAst", 2) should be (true)
  }

  it must "TestPMML" taggedAs(PythonTest) in {
    run("test.pmml", "TestPMML", 2) should be (true)
  }

  it must "TestSignature" taggedAs(PythonTest) in {
    run("test.signature", "TestSignature", 2) should be (true)
  }

  it must "TestTypeCheck" taggedAs(PythonTest) in {
    run("test.typecheck", "TestTypeCheck", 2) should be (true)
  }

}
