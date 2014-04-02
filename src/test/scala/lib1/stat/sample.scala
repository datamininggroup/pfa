package test.scala.lib1.stat.sample

import scala.collection.JavaConversions._

import org.junit.runner.RunWith

import org.scalatest.FlatSpec
import org.scalatest.junit.JUnitRunner
import org.scalatest.Matchers

import org.scoringengine.pfa.data._
import org.scoringengine.pfa.jvmcompiler._
import org.scoringengine.pfa.errors._
import test.scala._

@RunWith(classOf[JUnitRunner])
class Lib1StatSampleSuite extends FlatSpec with Matchers {
  "sample mean" must "work in a local record" taggedAs(Lib1, Lib1StatSample) in {
    val engine = PFAEngine.fromYaml("""
input: "null"
output: double
action:
  - let:
      accumulator:
        value: {"sum_w": 0.0, "sum_wx": 0.0, "metadata": "some other information"}
        type: {type: record, name: Test, fields: [{name: sum_w, type: double}, {name: sum_wx, type: double}, {name: metadata, type: string}]}
  - {set: {accumulator: {stat.sample.updateMean: [accumulator, 1.0, 5.3]}}}
  - {set: {accumulator: {stat.sample.updateMean: [accumulator, 1.0, 5.8]}}}
  - {set: {accumulator: {stat.sample.updateMean: [accumulator, 1.0, 5.2]}}}
  - {set: {accumulator: {stat.sample.updateMean: [accumulator, 1.0, 5.7]}}}
  - {set: {accumulator: {stat.sample.updateMean: [accumulator, 1.0, 5.3]}}}
  - {stat.sample.mean: [accumulator]}
""").head
    engine.action(null).asInstanceOf[Double] should be (5.46 +- 0.01)

    evaluating { PFAEngine.fromYaml("""
input: "null"
output: double
action:
  - let:
      accumulator:
        value: {"SUM_W": 0.0, "SUM_WX": 0.0}
        type: {type: record, name: Test, fields: [{name: SUM_W, type: double}, {name: SUM_WX, type: double}]}
  - {stat.sample.mean: [accumulator]}
""").head } should produce [PFASemanticException]

  }

  it must "work in a cell" taggedAs(Lib1, Lib1StatSample) in {
    val engine = PFAEngine.fromYaml("""
input: "null"
output: double
cells:
  accumulator:
    type: {type: record, name: Test, fields: [{name: sum_w, type: double}, {name: sum_wx, type: double}, {name: metadata, type: string}]}
    init: {"sum_w": 0.0, "sum_wx": 0.0, "metadata": "some other information"}
action:
  - {cell: accumulator, to: {params: [{x: Test}], ret: Test, do: [{stat.sample.updateMean: [x, 1.0, 5.3]}]}}
  - {cell: accumulator, to: {params: [{x: Test}], ret: Test, do: [{stat.sample.updateMean: [x, 1.0, 5.8]}]}}
  - {cell: accumulator, to: {params: [{x: Test}], ret: Test, do: [{stat.sample.updateMean: [x, 1.0, 5.2]}]}}
  - {cell: accumulator, to: {params: [{x: Test}], ret: Test, do: [{stat.sample.updateMean: [x, 1.0, 5.7]}]}}
  - {cell: accumulator, to: {params: [{x: Test}], ret: Test, do: [{stat.sample.updateMean: [x, 1.0, 5.3]}]}}
#  - {log: [{cell: accumulator, path: [[metadata]]}]}
  - {stat.sample.mean: [{cell: accumulator}]}
""").head
    engine.action(null).asInstanceOf[Double] should be (5.46 +- 0.01)

    evaluating { PFAEngine.fromYaml("""
input: "null"
output: double
cells:
  accumulator:
    type: {type: record, name: Test, fields: [{name: SUM_W, type: double}, {name: SUM_WX, type: double}]}
    init: {"SUM_W": 0.0, "SUM_WX": 0.0}
action:
  - {cell: accumulator, to: {params: [{x: Test}], ret: Test, do: [{stat.sample.updateMean: [x, 1.0, 5.3]}]}}
  - {stat.sample.mean: [{cell: accumulator}]}
""").head } should produce [PFASemanticException]
  }

}
