package org.scoringengine.pfa.lib1.model

import scala.annotation.tailrec

import org.apache.avro.AvroRuntimeException
import org.apache.avro.SchemaCompatibility.checkReaderWriterCompatibility
import org.apache.avro.SchemaCompatibility.SchemaCompatibilityType

import org.scoringengine.pfa.ast.LibFcn
import org.scoringengine.pfa.errors.PFARuntimeException
import org.scoringengine.pfa.jvmcompiler.JavaCode
import org.scoringengine.pfa.jvmcompiler.javaSchema

import org.scoringengine.pfa.ast.AstContext
import org.scoringengine.pfa.ast.ExpressionContext
import org.scoringengine.pfa.ast.FcnDef
import org.scoringengine.pfa.ast.FcnRef

import org.scoringengine.pfa.data.PFAArray
import org.scoringengine.pfa.data.PFARecord
import org.scoringengine.pfa.data.ComparisonOperator

import org.scoringengine.pfa.signature.P
import org.scoringengine.pfa.signature.Sig
import org.scoringengine.pfa.signature.Signature
import org.scoringengine.pfa.signature.Sigs

import org.scoringengine.pfa.types.Type
import org.scoringengine.pfa.types.FcnType
import org.scoringengine.pfa.types.AvroType
import org.scoringengine.pfa.types.AvroNull
import org.scoringengine.pfa.types.AvroBoolean
import org.scoringengine.pfa.types.AvroInt
import org.scoringengine.pfa.types.AvroLong
import org.scoringengine.pfa.types.AvroFloat
import org.scoringengine.pfa.types.AvroDouble
import org.scoringengine.pfa.types.AvroBytes
import org.scoringengine.pfa.types.AvroFixed
import org.scoringengine.pfa.types.AvroString
import org.scoringengine.pfa.types.AvroEnum
import org.scoringengine.pfa.types.AvroArray
import org.scoringengine.pfa.types.AvroMap
import org.scoringengine.pfa.types.AvroRecord
import org.scoringengine.pfa.types.AvroField
import org.scoringengine.pfa.types.AvroUnion

package object tree {
  private var fcns = Map[String, LibFcn]()
  def provides = fcns
  def provide(libFcn: LibFcn): Unit =
    fcns = fcns + Tuple2(libFcn.name, libFcn)

  val prefix = "model.tree."

  //////////////////////////////////////////////////////////////////// 

  ////   simpleWalk (SimpleWalk)
  object SimpleWalk extends LibFcn {
    val name = prefix + "simpleWalk"
    val sig = Sig(List(
      "datum" -> P.WildRecord("D", Map()),
      "treeNode" -> P.WildRecord("T", Map(
        "field" -> P.String,
        "operator" -> P.String,
        "value" -> P.Wildcard("V"),
        "pass" -> P.Union(List(P.WildRecord("T", Map()), P.Wildcard("S"))),
        "fail" -> P.Union(List(P.WildRecord("T", Map()), P.Wildcard("S")))))),
      P.Wildcard("S"))
    val doc =
      <doc>
        <desc>Descend through a tree comparing <p>datum</p> to each branch with a simple predicate, stopping at a leaf of type <tp>S</tp>.</desc>
        <param name="datum">An element of the dataset to score with the tree.</param>
        <param name="treeNode">A node of the decision or regression tree.
          <paramField name="field">Indicates the field of <p>datum</p> to test.  Fields may have any type.</paramField>
          <paramField name="operator">One of "==" (equal), "!=" (not equal), "&lt;" (less than), "&lt;=" (less or equal), "&gt;" (greater than), or "&gt;=" (greater or equal).</paramField>
          <paramField name="value">Value for comparison.  Should be the union of or otherwise broader than all <p>datum</p> fields under consideration.</paramField>
          <paramField name="pass">Branch to return if field <pf>field</pf> of <p>datum</p> <p>operator</p> <p>value</p> yields <c>true</c>.</paramField>
          <paramField name="fail">Branch to return if field <pf>field</pf> of <p>datum</p> <p>operator</p> <p>value</p> yields <c>false</c>.</paramField>
        </param>
        <ret>The score associated with the destination leaf, which may be any type <tp>S</tp>.  If <tp>S</tp> is a <t>string</t>, this is generally called a decision tree; if a <t>double</t>, it is a regression tree; if an <t>array</t> of <t>double</t>, a multivariate regression tree, etc.</ret>
        <error>Raises a "no such field" error if <pf>field</pf> is not a field of <p>datum</p>.</error>
        <error>Raises an "invalid comparison operator" error if <pf>operator</pf> is not one of "==", "!=", "&lt;", "&lt;=", "&gt;", or "&gt;=".</error>
        <error>Raises a "bad value type" error if the <pf>field</pf> of <p>datum</p> cannot be upcast to <tp>V</tp>.</error>
      </doc>
    @tailrec
    def apply(datum: PFARecord, treeNode: PFARecord): AnyRef = {
      val fieldName = treeNode.get("field").asInstanceOf[String]
      val fieldValue = try {
        datum.get(fieldName)
      }
      catch {
        case err: AvroRuntimeException => throw new PFARuntimeException("no such field")
      }

      val fieldSchema = datum.getSchema.getField(fieldName).schema
      val valueSchema = treeNode.getSchema.getField("value").schema

      if (checkReaderWriterCompatibility(valueSchema, fieldSchema).getType != SchemaCompatibilityType.COMPATIBLE)
        throw new PFARuntimeException("bad value type")

      val comparisonOperator =
        treeNode.get("operator") match {
          case "<=" => new ComparisonOperator(valueSchema, -3)
          case "<" => new ComparisonOperator(valueSchema, -2)
          case "!=" => new ComparisonOperator(valueSchema, -1)
          case "==" => new ComparisonOperator(valueSchema, 1)
          case ">=" => new ComparisonOperator(valueSchema, 2)
          case ">" => new ComparisonOperator(valueSchema, 3)
          case _ => throw new PFARuntimeException("invalid comparison operator")
        }

      val treeValue = treeNode.get("value")

      val upcastFieldValue = (fieldValue, treeValue) match {
        case (x: java.lang.Integer, _: java.lang.Long) => java.lang.Long.valueOf(x.longValue)
        case (x: java.lang.Integer, _: java.lang.Float) => java.lang.Float.valueOf(x.floatValue)
        case (x: java.lang.Integer, _: java.lang.Double) => java.lang.Double.valueOf(x.doubleValue)

        case (x: java.lang.Long, _: java.lang.Float) => java.lang.Float.valueOf(x.floatValue)
        case (x: java.lang.Long, _: java.lang.Double) => java.lang.Double.valueOf(x.doubleValue)

        case (x: java.lang.Float, _: java.lang.Double) => java.lang.Double.valueOf(x.doubleValue)

        case _ => fieldValue
      }

      val next =
        if (comparisonOperator.apply(upcastFieldValue, treeValue))
          treeNode.get("pass")
        else
          treeNode.get("fail")

      next match {
        case x: PFARecord if (treeNode.getSchema.getFullName == x.getSchema.getFullName) => apply(datum, x)
        case x => x
      }
    }
  }
  provide(SimpleWalk)

  ////   predicateWalk (PredicateWalk)
  object PredicateWalk extends LibFcn {
    val name = prefix + "predicateWalk"
    val sig = Sig(List(
      "datum" -> P.WildRecord("D", Map()),
      "treeNode" -> P.WildRecord("T", Map(
        "pass" -> P.Union(List(P.WildRecord("T", Map()), P.Wildcard("S"))),
        "fail" -> P.Union(List(P.WildRecord("T", Map()), P.Wildcard("S"))))),
      "predicate" -> P.Fcn(List(P.WildRecord("D", Map()), P.WildRecord("T", Map())), P.Boolean)),
      P.Wildcard("S"))
    val doc =
      <doc>
        <desc>Descend through a tree comparing <p>datum</p> to each branch with a user-defined predicate, stopping at a leaf of type <tp>S</tp>.</desc>
        <param name="datum">An element of the dataset to score with the tree.</param>
        <param name="treeNode">A node of the decision or regression tree.
          <paramField name="pass">Branch to return if <c>{{"predicate": ["datum", "treeNode"]}}</c> yields <c>true</c>.</paramField>
          <paramField name="fail">Branch to return if <c>{{"predicate": ["datum", "treeNode"]}}</c> yields <c>false</c>.</paramField>
        </param>
        <ret>The score associated with the destination leaf, which may be any type <tp>S</tp>.  If <tp>S</tp> is a <t>string</t>, this is generally called a decision tree; if a <t>double</t>, it is a regression tree; if an <t>array</t> of <t>double</t>, a multivariate regression tree, etc.</ret>
      </doc>
    @tailrec
    def apply(datum: PFARecord, treeNode: PFARecord, predicate: (PFARecord, PFARecord) => Boolean): AnyRef = {
      val next =
        if (predicate(datum, treeNode))
          treeNode.get("pass")
        else
          treeNode.get("fail")

      next match {
        case x: PFARecord if (treeNode.getSchema.getFullName == x.getSchema.getFullName) => apply(datum, x, predicate)
        case x => x
      }
    }
  }
  provide(PredicateWalk)

}
