package org.scoringengine.pfa.lib1

import org.scoringengine.pfa.ast.LibFcn
import org.scoringengine.pfa.errors.PFARuntimeException
import org.scoringengine.pfa.jvmcompiler.JavaCode
import org.scoringengine.pfa.jvmcompiler.javaSchema

import org.scoringengine.pfa.ast.AstContext
import org.scoringengine.pfa.ast.ExpressionContext
import org.scoringengine.pfa.ast.FcnDef
import org.scoringengine.pfa.ast.FcnRef

import org.scoringengine.pfa.datatype.Type
import org.scoringengine.pfa.datatype.FcnType
import org.scoringengine.pfa.datatype.AvroType
import org.scoringengine.pfa.datatype.AvroNull
import org.scoringengine.pfa.datatype.AvroBoolean
import org.scoringengine.pfa.datatype.AvroInt
import org.scoringengine.pfa.datatype.AvroLong
import org.scoringengine.pfa.datatype.AvroFloat
import org.scoringengine.pfa.datatype.AvroDouble
import org.scoringengine.pfa.datatype.AvroBytes
import org.scoringengine.pfa.datatype.AvroFixed
import org.scoringengine.pfa.datatype.AvroString
import org.scoringengine.pfa.datatype.AvroEnum
import org.scoringengine.pfa.datatype.AvroArray
import org.scoringengine.pfa.datatype.AvroMap
import org.scoringengine.pfa.datatype.AvroRecord
import org.scoringengine.pfa.datatype.AvroField
import org.scoringengine.pfa.datatype.AvroUnion

package object map {
  private var fcns = Map[String, LibFcn]()
  def provides = fcns
  def provide(libFcn: LibFcn): Unit =
    fcns = fcns + Tuple2(libFcn.name, libFcn)

  val prefix = "map."

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
