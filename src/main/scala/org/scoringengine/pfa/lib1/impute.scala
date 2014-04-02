package org.scoringengine.pfa.lib1

import org.scoringengine.pfa.ast.LibFcn
import org.scoringengine.pfa.errors.PFARuntimeException
import org.scoringengine.pfa.jvmcompiler.JavaCode
import org.scoringengine.pfa.jvmcompiler.javaSchema

import org.scoringengine.pfa.ast.AstContext
import org.scoringengine.pfa.ast.ExpressionContext
import org.scoringengine.pfa.ast.FcnDef
import org.scoringengine.pfa.ast.FcnRef

import org.scoringengine.pfa.data.PFAArray
import org.scoringengine.pfa.data.PFAEnumSymbol
import org.scoringengine.pfa.data.PFAFixed
import org.scoringengine.pfa.data.PFAMap
import org.scoringengine.pfa.data.PFARecord

import org.scoringengine.pfa.jvmcompiler.javaType

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

package object impute {
  private var fcns = Map[String, LibFcn]()
  def provides = fcns
  def provide(libFcn: LibFcn): Unit =
    fcns = fcns + Tuple2(libFcn.name, libFcn)

  val prefix = "impute."

  // TODO: errorOnNaN, defaultOnNaN, errorOnInf, defaultOnInf
  // functions that keep a running average in a cell...
  // functors that take an handler function...

  ////   errorOnNull (ErrorOnNull)
  object ErrorOnNull extends LibFcn {
    val name = prefix + "errorOnNull"
    val sig = Sig(List("x" -> P.Union(List(P.Wildcard("A"), P.Null))), P.Wildcard("A"))
    val doc =
      <doc>
        <desc>Skip an action by raising an "encountered null" runtime error when <p>x</p> is <c>null</c>.</desc>
      </doc>
    override def javaRef(fcnType: FcnType): JavaCode = fcnType.ret match {
      case _: AvroBoolean => JavaCode(DoBoolean.getClass.getName + ".MODULE$")
      case _: AvroInt => JavaCode(DoInt.getClass.getName + ".MODULE$")
      case _: AvroLong => JavaCode(DoLong.getClass.getName + ".MODULE$")
      case _: AvroFloat => JavaCode(DoFloat.getClass.getName + ".MODULE$")
      case _: AvroDouble => JavaCode(DoDouble.getClass.getName + ".MODULE$")
      case _: AvroBytes => JavaCode(DoBytes.getClass.getName + ".MODULE$")
      case _: AvroFixed => JavaCode(DoFixed.getClass.getName + ".MODULE$")
      case _: AvroString => JavaCode(DoString.getClass.getName + ".MODULE$")
      case _: AvroEnum => JavaCode(DoEnum.getClass.getName + ".MODULE$")
      case _: AvroArray => JavaCode(DoArray.getClass.getName + ".MODULE$")
      case _: AvroMap => JavaCode(DoMap.getClass.getName + ".MODULE$")
      case _: AvroRecord => JavaCode(DoRecord.getClass.getName + ".MODULE$")
    }
    object DoBoolean {
      def apply(x: java.lang.Boolean): Boolean = x match {
        case null => throw new PFARuntimeException("encountered null")
        case _ => x.asInstanceOf[java.lang.Boolean].booleanValue
      }
    }
    object DoInt {
      def apply(x: AnyRef): Int = x match {
        case null => throw new PFARuntimeException("encountered null")
        case _ => x.asInstanceOf[java.lang.Integer].intValue
      }
    }
    object DoLong {
      def apply(x: AnyRef): Long = x match {
        case null => throw new PFARuntimeException("encountered null")
        case _ => x.asInstanceOf[java.lang.Long].longValue
      }
    }
    object DoFloat {
      def apply(x: AnyRef): Float = x match {
        case null => throw new PFARuntimeException("encountered null")
        case _ => x.asInstanceOf[java.lang.Float].floatValue
      }
    }
    object DoDouble {
      def apply(x: AnyRef): Double = x match {
        case null => throw new PFARuntimeException("encountered null")
        case _ => x.asInstanceOf[java.lang.Double].doubleValue
      }
    }
    object DoBytes {
      def apply(x: AnyRef): Array[Byte] = x match {
        case null => throw new PFARuntimeException("encountered null")
        case _ => x.asInstanceOf[Array[Byte]]
      }
    }
    object DoFixed {
      def apply(x: AnyRef): PFAFixed = x match {
        case null => throw new PFARuntimeException("encountered null")
        case _ => x.asInstanceOf[PFAFixed]
      }
    }
    object DoString {
      def apply(x: AnyRef): String = x match {
        case null => throw new PFARuntimeException("encountered null")
        case _ => x.asInstanceOf[String]
      }
    }
    object DoEnum {
      def apply(x: AnyRef): PFAEnumSymbol = x match {
        case null => throw new PFARuntimeException("encountered null")
        case _ => x.asInstanceOf[PFAEnumSymbol]
      }
    }
    object DoArray {
      def apply(x: AnyRef): PFAArray[_] = x match {
        case null => throw new PFARuntimeException("encountered null")
        case _ => x.asInstanceOf[PFAArray[_]]
      }
    }
    object DoMap {
      def apply(x: AnyRef): PFAMap[_] = x match {
        case null => throw new PFARuntimeException("encountered null")
        case _ => x.asInstanceOf[PFAMap[_]]
      }
    }
    object DoRecord {
      def apply(x: AnyRef): PFARecord = x match {
        case null => throw new PFARuntimeException("encountered null")
        case _ => x.asInstanceOf[PFARecord]
      }
    }
  }
  provide(ErrorOnNull)

  ////   defaultOnNull (DefaultOnNull)
  object DefaultOnNull extends LibFcn {
    val name = prefix + "defaultOnNull"
    val sig = Sig(List("x" -> P.Union(List(P.Wildcard("A"), P.Null)), "default" -> P.Wildcard("A")), P.Wildcard("A"))
    val doc =
      <doc>
        <desc>Replace <c>null</c> values in <p>x</p> with <p>default</p>.</desc>
      </doc>
    override def javaRef(fcnType: FcnType): JavaCode = fcnType.ret match {
      case _: AvroBoolean => JavaCode(DoBoolean.getClass.getName + ".MODULE$")
      case _: AvroInt => JavaCode(DoInt.getClass.getName + ".MODULE$")
      case _: AvroLong => JavaCode(DoLong.getClass.getName + ".MODULE$")
      case _: AvroFloat => JavaCode(DoFloat.getClass.getName + ".MODULE$")
      case _: AvroDouble => JavaCode(DoDouble.getClass.getName + ".MODULE$")
      case _: AvroBytes => JavaCode(DoBytes.getClass.getName + ".MODULE$")
      case _: AvroFixed => JavaCode(DoFixed.getClass.getName + ".MODULE$")
      case _: AvroString => JavaCode(DoString.getClass.getName + ".MODULE$")
      case _: AvroEnum => JavaCode(DoEnum.getClass.getName + ".MODULE$")
      case _: AvroArray => JavaCode(DoArray.getClass.getName + ".MODULE$")
      case _: AvroMap => JavaCode(DoMap.getClass.getName + ".MODULE$")
      case _: AvroRecord => JavaCode(DoRecord.getClass.getName + ".MODULE$")
    }
    object DoBoolean {
      def apply(x: java.lang.Boolean, default: Boolean): Boolean = x match {
        case null => default
        case _ => x.asInstanceOf[java.lang.Boolean].booleanValue
      }
    }
    object DoInt {
      def apply(x: AnyRef, default: Int): Int = x match {
        case null => default
        case _ => x.asInstanceOf[java.lang.Integer].intValue
      }
    }
    object DoLong {
      def apply(x: AnyRef, default: Long): Long = x match {
        case null => default
        case _ => x.asInstanceOf[java.lang.Long].longValue
      }
    }
    object DoFloat {
      def apply(x: AnyRef, default: Float): Float = x match {
        case null => default
        case _ => x.asInstanceOf[java.lang.Float].floatValue
      }
    }
    object DoDouble {
      def apply(x: AnyRef, default: Double): Double = x match {
        case null => default
        case _ => x.asInstanceOf[java.lang.Double].doubleValue
      }
    }
    object DoBytes {
      def apply(x: AnyRef, default: Array[Byte]): Array[Byte] = x match {
        case null => default
        case _ => x.asInstanceOf[Array[Byte]]
      }
    }
    object DoFixed {
      def apply(x: AnyRef, default: PFAFixed): PFAFixed = x match {
        case null => default
        case _ => x.asInstanceOf[PFAFixed]
      }
    }
    object DoString {
      def apply(x: AnyRef, default: String): String = x match {
        case null => default
        case _ => x.asInstanceOf[String]
      }
    }
    object DoEnum {
      def apply(x: AnyRef, default: PFAEnumSymbol): PFAEnumSymbol = x match {
        case null => default
        case _ => x.asInstanceOf[PFAEnumSymbol]
      }
    }
    object DoArray {
      def apply[X](x: AnyRef, default: PFAArray[X]): PFAArray[X] = x match {
        case null => default
        case _ => x.asInstanceOf[PFAArray[X]]
      }
    }
    object DoMap {
      def apply[X <: AnyRef](x: AnyRef, default: PFAMap[X]): PFAMap[X] = x match {
        case null => default
        case _ => x.asInstanceOf[PFAMap[X]]
      }
    }
    object DoRecord {
      def apply(x: AnyRef, default: PFARecord): PFARecord = x match {
        case null => default
        case _ => x.asInstanceOf[PFARecord]
      }
    }
  }
  provide(DefaultOnNull)

}
