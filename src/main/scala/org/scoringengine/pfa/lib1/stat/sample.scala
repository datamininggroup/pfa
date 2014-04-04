package org.scoringengine.pfa.lib1.stat

import scala.annotation.tailrec
import scala.collection.immutable.ListMap

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

package object sample {
  private var fcns = Map[String, LibFcn]()
  def provides = fcns
  def provide(libFcn: LibFcn): Unit =
    fcns = fcns + Tuple2(libFcn.name, libFcn)

  val prefix = "stat.sample."

  //////////////////////////////////////////////////////////////////// 

  ////   updateMean (UpdateMean)
  object UpdateMean extends LibFcn {
    val name = prefix + "updateMean"
    val sig = Sig(List("runningSum" -> P.WildRecord("A", ListMap("sum_w" -> P.Double, "sum_wx" -> P.Double)), "w" -> P.Double, "x" -> P.Double), P.Wildcard("A"))
    val doc =
      <doc>
        <desc>Update a record containing running sums for computing a sample mean.</desc>
        <param name="runningSum">Record of partial sums: <c>sum_w</c> is the sum of weights, <c>sum_wx</c> is the sum of weights times sample values.</param>
        <param name="w">Weight for this sample, which should be 1 for an unweighted mean.</param>
        <param name="x">Sample value.</param>
        <detail>Use <f>{Mean.name}</f> to get the mean.</detail>
      </doc>
    def apply(record: PFARecord, w: Double, x: Double): PFARecord = {
      val sum_w = record.get("sum_w").asInstanceOf[Double]
      val sum_wx = record.get("sum_wx").asInstanceOf[Double]
      record.multiUpdate(Array("sum_w", "sum_wx"), Array(sum_w + w, sum_wx + (w * x)))
    }
  }
  provide(UpdateMean)

  ////   mean (Mean)
  object Mean extends LibFcn {
    val name = prefix + "mean"
    val sig = Sig(List("runningSum" -> P.WildRecord("A", ListMap("sum_w" -> P.Double, "sum_wx" -> P.Double))), P.Double)
    val doc =
      <doc>
        <desc>Compute the mean from a <p>runningSum</p> record.</desc>
        <detail>Use <f>{UpdateMean.name}</f> to fill the record.</detail>
      </doc>
    def apply(record: PFARecord): Double =
      record.get("sum_wx").asInstanceOf[Double] / record.get("sum_w").asInstanceOf[Double]
  }
  provide(Mean)

}
