package test.scala.lib1.model.tree

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
  "tree model" must "simpleWalk" taggedAs(Lib1, Lib1ModelTree) in {
    val engine = PFAEngine.fromYaml("""
input: {type: record, name: Datum, fields: [{name: one, type: int}, {name: two, type: double}, {name: three, type: string}]}
output: string
cells:
  tree:
    type:
      type: record
      name: TreeNode
      fields:
        - {name: field, type: string}
        - {name: operator, type: string}
        - {name: value, type: [double, string]}
        - {name: pass, type: [string, TreeNode]}
        - {name: fail, type: [string, TreeNode]}
    init:
      field: one
      operator: "<"
      value: {double: 12}
      pass:
        TreeNode:
          field: two
          operator: ">"
          value: {double: 3.5}
          pass: {string: yes-yes}
          fail: {string: yes-no}
      fail:
        TreeNode:
          field: three
          operator: ==
          value: {string: TEST}
          pass: {string: no-yes}
          fail: {string: no-no}
action:
  - {model.tree.simpleWalk: [input, {cell: tree}]}
""").head

    engine.action(engine.fromJson("""{"one": 1, "two": 7, "three": "whatever"}""", engine.inputType)) should be ("yes-yes")
    engine.action(engine.fromJson("""{"one": 1, "two": 0, "three": "whatever"}""", engine.inputType)) should be ("yes-no")
    engine.action(engine.fromJson("""{"one": 15, "two": 7, "three": "TEST"}""", engine.inputType)) should be ("no-yes")
    engine.action(engine.fromJson("""{"one": 15, "two": 7, "three": "ZEST"}""", engine.inputType)) should be ("no-no")
  }

  it must "predicateWalk" taggedAs(Lib1, Lib1ModelTree) in {
    val engine = PFAEngine.fromYaml("""
input: {type: record, name: Datum, fields: [{name: one, type: int}, {name: two, type: double}, {name: three, type: string}]}
output: string
cells:
  tree:
    type:
      type: record
      name: TreeNode
      fields:
        - {name: field, type: string}
        - {name: pass, type: [string, TreeNode]}
        - {name: fail, type: [string, TreeNode]}
    init:
      field: one
      pass:
        TreeNode:
          field: two
          pass: {string: yes-yes}
          fail: {string: yes-no}
      fail:
        TreeNode:
          field: three
          pass: {string: no-yes}
          fail: {string: no-no}
action:
  - {model.tree.predicateWalk: [input, {cell: tree}, {fcnref: u.myPredicate}]}
fcns:
  myPredicate:
    params:
      - datum: Datum
      - treeNode: TreeNode
    ret: boolean
    do:
      cond:
        - {if: {"==": [treeNode.field, [one]]}, then: {"<": [datum.one, 12]}}
        - {if: {"==": [treeNode.field, [two]]}, then: {">": [datum.two, 3.5]}}
      else: {"==": [datum.three, [TEST]]}
""").head

    engine.action(engine.fromJson("""{"one": 1, "two": 7, "three": "whatever"}""", engine.inputType)) should be ("yes-yes")
    engine.action(engine.fromJson("""{"one": 1, "two": 0, "three": "whatever"}""", engine.inputType)) should be ("yes-no")
    engine.action(engine.fromJson("""{"one": 15, "two": 7, "three": "TEST"}""", engine.inputType)) should be ("no-yes")
    engine.action(engine.fromJson("""{"one": 15, "two": 7, "three": "ZEST"}""", engine.inputType)) should be ("no-no")
  }

}
