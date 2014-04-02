package org.scoringengine.pfa.lib1

import org.scoringengine.pfa.ast.LibFcn
import org.scoringengine.pfa.errors.PFARuntimeException
import org.scoringengine.pfa.jvmcompiler.JavaCode
import org.scoringengine.pfa.jvmcompiler.javaSchema

import org.scoringengine.pfa.ast.AstContext
import org.scoringengine.pfa.ast.ExpressionContext
import org.scoringengine.pfa.ast.FcnDef
import org.scoringengine.pfa.ast.FcnRef

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

package object fixed {
  private var fcns = Map[String, LibFcn]()
  def provides = fcns
  def provide(libFcn: LibFcn): Unit =
    fcns = fcns + Tuple2(libFcn.name, libFcn)

  val prefix = "fixed."

  //////////////////////////////////////////////////////////////////// basic access

  // ////   len (Len)
  // object Len extends LibFcn {
  //   val name = prefix + "len"
  //   val sig = Sig(List("s" -> AvroString()), AvroInt())
  //   val doc =
  //     <doc>
  //       <desc>Return the length of a string.</desc>
  //     </doc>
  //   def apply(s: String): Int = s.size
  // }
  // provide(Len)

}
