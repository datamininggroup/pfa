package org.scoringengine.pfa

import scala.collection.mutable
import scala.language.postfixOps

import org.scoringengine.pfa.types.Type
import org.scoringengine.pfa.types.FcnType
import org.scoringengine.pfa.types.AvroType
import org.scoringengine.pfa.types.AvroCompiled
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

package signature {
  class IncompatibleTypes(message: String) extends Exception(message)

  trait Pattern
  object P {
    case object Null extends Pattern
    case object Boolean extends Pattern
    case object Int extends Pattern
    case object Long extends Pattern
    case object Float extends Pattern
    case object Double extends Pattern
    case object Bytes extends Pattern
    case object String extends Pattern

    case class Array(items: Pattern) extends Pattern
    case class Map(values: Pattern) extends Pattern
    case class Union(types: List[Pattern]) extends Pattern

    case class Fixed(size: Int, fullName: Option[String] = None) extends Pattern
    case class Enum(symbols: List[String], fullName: Option[String] = None) extends Pattern
    case class Record(fields: scala.collection.immutable.Map[String, Pattern], fullName: Option[String] = None) extends Pattern

    case class Fcn(params: List[Pattern], ret: Pattern) extends Pattern

    case class Wildcard(label: String, oneOf: Set[Type] = Set[Type]()) extends Pattern
    case class WildRecord(label: String, minimalFields: scala.collection.immutable.Map[String, Pattern]) extends Pattern

    def toType(pat: Pattern): Type = pat match {
      case Null => AvroNull()
      case Boolean => AvroBoolean()
      case Int => AvroInt()
      case Long => AvroLong()
      case Float => AvroFloat()
      case Double => AvroDouble()
      case Bytes => AvroBytes()
      case String => AvroString()

      case Array(items) => AvroArray(toType(items).asInstanceOf[AvroType])
      case Map(values) => AvroMap(toType(values).asInstanceOf[AvroType])
      case Union(types) => AvroUnion(types.map(toType(_).asInstanceOf[AvroType]))

      case Fixed(size, Some(fullName)) => AvroFixed(size, fullName.split("\\.").last, (fullName.split("\\.").init.mkString(".") match { case "" => None;  case x => Some(x) }))
      case Fixed(size, None) => AvroFixed(size)

      case Enum(symbols, Some(fullName)) => AvroEnum(symbols, fullName.split("\\.").last, (fullName.split("\\.").init.mkString(".") match { case "" => None;  case x => Some(x) }))
      case Enum(symbols, None) => AvroEnum(symbols)

      case Record(fields, Some(fullName)) => AvroRecord(fields map {case (k, t) => AvroField(k, mustBeAvro(toType(t)))} toSeq, fullName.split("\\.").last, (fullName.split("\\.").init.mkString(".") match { case "" => None;  case x => Some(x) }))
      case Record(fields, None) => AvroRecord(fields map {case (k, t) => AvroField(k, mustBeAvro(toType(t)))} toSeq)

      case Fcn(params, ret) => FcnType(params.map(toType), toType(ret).asInstanceOf[AvroType])
    }

    def fromType(t: Type): Pattern = t match {
      case AvroNull() => Null
      case AvroBoolean() => Boolean
      case AvroInt() => Int
      case AvroLong() => Long
      case AvroFloat() => Float
      case AvroDouble() => Double
      case AvroBytes() => Bytes
      case AvroString() => String

      case AvroArray(items) => Array(fromType(items))
      case AvroMap(values) => Map(fromType(values))
      case AvroUnion(types) => Union(types.map(fromType(_)).toList)

      case AvroFixed(size, name, Some(namespace), _, _) => Fixed(size, Some(namespace + "." + name))
      case AvroFixed(size, name, None, _, _) => Fixed(size, Some(name))

      case AvroEnum(symbols, name, Some(namespace), _, _) => Enum(symbols, Some(namespace + "." + name))
      case AvroEnum(symbols, name, None, _, _) => Enum(symbols, Some(name))

      case AvroRecord(fields, name, Some(namespace), _, _) => Record(scala.collection.immutable.Map[String, Pattern](), Some(namespace + "." + name))
      case AvroRecord(fields, name, None, _, _) => Record(scala.collection.immutable.Map[String, Pattern](), Some(name))

      case FcnType(params, ret) => Fcn(params.map(fromType).toList, fromType(ret))
    }

    def mustBeAvro(t: Type): AvroType = t match {
      case x: AvroType => x
      case x => throw new IncompatibleTypes(x.toString + " is not an Avro type")
    }
  }

  object LabelData {
    private def appendTypes(candidates: List[Type], in: List[Type]): List[Type] = {
      var out = in
      for (candidate <- candidates) candidate match {
        case AvroUnion(types) =>
          out = appendTypes(types.toList, out)
        case x =>
          if (out exists {y => y.accepts(x)}) { }
          else {
            out indexWhere {y => x.accepts(y)} match {
              case -1 => out = x :: out
              case i => out = out.updated(i, x)
            }
          }
      }
      out
    }

    def distinctTypes(candidates: List[Type]): List[Type] = {
      var out: List[Type] = Nil
      out = appendTypes(candidates, out)
      out.reverse
    }

    def broadestType(candidates: List[Type]): Type = {
      if (candidates.isEmpty)
        throw new IncompatibleTypes("empty list of types")

      else if (candidates forall {case _: AvroNull => true; case _ => false})
        candidates.head
      else if (candidates forall {case _: AvroBoolean => true; case _ => false})
        candidates.head

      else if (candidates forall {case _: AvroInt => true; case _ => false})
        candidates.head
      else if (candidates forall {case _: AvroInt | _: AvroLong => true; case _ => false})
        candidates collectFirst {case x: AvroLong => x} get
      else if (candidates forall {case _: AvroInt | _: AvroLong | _: AvroFloat => true; case _ => false})
        candidates collectFirst {case x: AvroFloat => x} get
      else if (candidates forall {case _: AvroInt | _: AvroLong | _: AvroFloat | _: AvroDouble => true; case _ => false})
        candidates collectFirst {case x: AvroDouble => x} get

      else if (candidates forall {case _: AvroBytes => true; case _ => false})
        candidates.head
      else if (candidates forall {case _: AvroString => true; case _ => false})
        candidates.head

      else if (candidates forall {case _: AvroArray => true; case _ => false})
        AvroArray(P.mustBeAvro(broadestType(candidates map {case AvroArray(items) => items})))

      else if (candidates forall {case _: AvroMap => true; case _ => false})
        AvroMap(P.mustBeAvro(broadestType(candidates map {case AvroMap(values) => values})))

      else if (candidates forall {case _: AvroUnion => true; case _ => false})
        AvroUnion(distinctTypes(candidates flatMap {case AvroUnion(types) => types}).map(P.mustBeAvro))

      else if (candidates forall {case _: AvroFixed => true; case _ => false}) {
        val fullName = candidates.head.asInstanceOf[AvroFixed].fullName
        if (candidates.tail forall {case x: AvroFixed => x.fullName == fullName})
          candidates.head
        else
          throw new IncompatibleTypes("incompatible fixed types: " + candidates.mkString(" "))
      }

      else if (candidates forall {case _: AvroEnum => true; case _ => false}) {
        val fullName = candidates.head.asInstanceOf[AvroEnum].fullName
        if (candidates.tail forall {case x: AvroEnum => x.fullName == fullName})
          candidates.head
        else
          throw new IncompatibleTypes("incompatible enum types: " + candidates.mkString(" "))
      }

      else if (candidates forall {case _: AvroRecord => true; case _ => false}) {
        val fullName = candidates.head.asInstanceOf[AvroRecord].fullName
        if (candidates.tail forall {case x: AvroRecord => x.fullName == fullName})
          candidates.head
        else
          AvroUnion(distinctTypes(candidates).map(P.mustBeAvro))
      }

      else if (candidates forall {case _: FcnType => true; case _ => false}) {
        val params = candidates.head.asInstanceOf[FcnType].params
        val ret = candidates.head.asInstanceOf[FcnType].ret

        if (candidates.tail forall {case FcnType(p, r) => p == params  &&  r == ret})
          candidates.head
        else
          throw new IncompatibleTypes("incompatible function types: " + candidates.mkString(" "))
      }

      else {
        val types = distinctTypes(candidates).map(P.mustBeAvro)
        if ((types collect {case _: AvroFixed => true} size) > 1)
          throw new IncompatibleTypes("incompatible fixed types: " + (candidates collect {case x: AvroFixed => x} mkString(" ")))
        if ((types collect {case _: AvroEnum => true} size) > 1)
          throw new IncompatibleTypes("incompatible enum types: " + (candidates collect {case x: AvroEnum => x} mkString(" ")))
        AvroUnion(types)
      }
    }
  }

  class LabelData {
    private var members: List[Type] = Nil
    def add(t: Type): Unit = {members = t :: members}
    def determineAssignment: Type = LabelData.broadestType(members)
  }

  trait Signature {
    def accepts(args: Seq[Type]): Option[(Seq[Type], AvroType)]
  }

  case class Sigs(cases: Seq[Sig]) extends Signature {
    def accepts(args: Seq[Type]): Option[(Seq[Type], AvroType)] =
      cases.view flatMap {_.accepts(args)} headOption
  }

  case class Sig(params: Seq[(String, Pattern)], ret: Pattern) extends Signature {
    def accepts(args: Seq[Type]): Option[(Seq[Type], AvroType)] = {
      val labelData = mutable.Map[String, LabelData]()
      if (params.corresponds(args)({case ((n, p), a) => check(p, a, labelData, false, false)})) {
        try {
          val assignments = labelData map {case (l, ld) => (l, ld.determineAssignment)} toMap
          val assignedParams = params.zip(args) map {case ((n, p), a) => assign(p, a, assignments)}
          val assignedRet = assignRet(ret, assignments)
          Some((assignedParams, assignedRet))
        }
        catch {
          case _: IncompatibleTypes => None
        }
      }
      else
        None
    }

    private def check(pat: Pattern, arg: Type, labelData: mutable.Map[String, LabelData], strict: Boolean, reversed: Boolean): Boolean = (pat, arg) match {
      case (P.Null, AvroNull()) => true
      case (P.Boolean, AvroBoolean()) => true

      case (P.Int, _: AvroInt) => true
      case (P.Long, _: AvroLong) => true
      case (P.Float, _: AvroFloat) => true
      case (P.Double, _: AvroDouble) => true

      case (P.Long, _: AvroInt | _: AvroLong) if (!strict  &&  !reversed) => true
      case (P.Float, _: AvroInt | _: AvroLong | _: AvroFloat) if (!strict  &&  !reversed) => true
      case (P.Double, _: AvroInt | _: AvroLong | _: AvroFloat | _: AvroDouble) if (!strict  &&  !reversed) => true

      case (P.Int | P.Long, _: AvroLong) if (!strict  &&  reversed) => true
      case (P.Int | P.Long | P.Float, _: AvroFloat) if (!strict  &&  reversed) => true
      case (P.Int | P.Long | P.Float | P.Double, _: AvroDouble) if (!strict  &&  reversed) => true

      case (P.Bytes, AvroBytes()) => true
      case (P.String, AvroString()) => true

      case (P.Array(p), AvroArray(a)) => check(p, a, labelData, strict, reversed)
      case (P.Map(p), AvroMap(a)) => check(p, a, labelData, strict, reversed)
      case (P.Union(ptypes), AvroUnion(atypes)) => {
        val available = mutable.Map[Int, Pattern]((0 until ptypes.size) map {i => (i, ptypes(i))} : _*)
        atypes forall {a =>
          available find {case (i, p) => check(p, a, labelData, true, reversed)} match {
            case Some((i, p)) => {
              available.remove(i)
              true
            }
            case None => false
          }
        }
      }

      case (P.Fixed(_, Some(pFullName)), a: AvroFixed) => pFullName == a.fullName
      case (P.Fixed(psize, None), AvroFixed(asize, _, _, _, _)) => psize == asize

      case (P.Enum(_, Some(pFullName)), a: AvroEnum) => pFullName == a.fullName
      case (P.Enum(psymbols, None), a @ AvroEnum(asymbols, _, _, _, _)) => asymbols.toSet subsetOf psymbols.toSet

      case (P.Record(_, Some(pFullName)), a: AvroRecord) => pFullName == a.fullName
      case (P.Record(pfields, None), AvroRecord(afields, _, _, _, _)) => {
        val amap = afields map {case AvroField(name, avroType, _, _, _, _) => (name, avroType)} toMap

        if (pfields.keys.toSet == amap.keys.toSet)
          pfields forall {case (pn, pt) => check(pt, amap(pn), labelData, true, reversed)}
        else
          false
      }

      case (P.Fcn(pparam, pret), FcnType(aparams, aret)) =>
        pparam.corresponds(aparams)({case (p, a) => check(p, a, labelData, strict, true)})  &&
          check(pret, aret, labelData, strict, false)

      case (P.Wildcard(label, oneOf), a) => {
        if (oneOf.isEmpty  ||  oneOf.contains(a)) {
          if (!labelData.contains(label))
            labelData(label) = new LabelData
          labelData(label).add(a)
          true
        }
        else
          false
      }

      case (P.WildRecord(label, minimalFields), a @ AvroRecord(afields, _, _, _, _)) => {
        if (!labelData.contains(label))
          labelData(label) = new LabelData
        labelData(label).add(a)

        val amap = afields map {case AvroField(name, avroType, _, _, _, _) => (name, avroType)} toMap

        if (minimalFields.keys.toSet subsetOf amap.keys.toSet)
          minimalFields forall {case (pn, pt) => check(pt, amap(pn), labelData, true, reversed)}
        else
          false
      }

      case _ => false
    }

    private def assign(pat: Pattern, arg: Type, assignments: Map[String, Type]): Type = (pat, arg) match {
      case (P.Null, AvroNull()) => arg
      case (P.Boolean, AvroBoolean()) => arg

      case (P.Int, _: AvroInt) => AvroInt()
      case (P.Long, _: AvroInt | _: AvroLong) => AvroLong()
      case (P.Float, _: AvroInt | _: AvroLong | _: AvroFloat) => AvroFloat()
      case (P.Double, _: AvroInt | _: AvroLong | _: AvroFloat | _: AvroDouble) => AvroDouble()

      case (P.Bytes, AvroBytes()) => arg
      case (P.String, AvroString()) => arg

      case (P.Array(p), AvroArray(a)) => AvroArray(P.mustBeAvro(assign(p, a, assignments)))
      case (P.Map(p), AvroMap(a)) => AvroMap(P.mustBeAvro(assign(p, a, assignments)))
      case (P.Union(_), a: AvroUnion) => a

      case (_: P.Fixed, a: AvroFixed) => a
      case (_: P.Enum, a: AvroEnum) => a
      case (_: P.Record, a: AvroRecord) => a

      case (_: P.Fcn, a: FcnType) => a

      case (P.Wildcard(label, _), _) => assignments(label)
      case (P.WildRecord(label, _), _) => assignments(label)
    }

    private def assignRet(pat: Pattern, assignments: Map[String, Type]): AvroType = pat match {
      case P.Null => AvroNull()
      case P.Boolean => AvroBoolean()
      case P.Int => AvroInt()
      case P.Long => AvroLong()
      case P.Float => AvroFloat()
      case P.Double => AvroDouble()
      case P.Bytes => AvroBytes()
      case P.String => AvroString()

      case P.Array(p) => AvroArray(assignRet(p, assignments))
      case P.Map(p) => AvroMap(assignRet(p, assignments))
      case P.Union(types) => AvroUnion(types map {t => assignRet(t, assignments)})

      case x: P.Fixed => P.toType(x).asInstanceOf[AvroType]
      case x: P.Enum => P.toType(x).asInstanceOf[AvroType]
      case x: P.Record => P.toType(x).asInstanceOf[AvroType]
      case x: P.Fcn => P.toType(x).asInstanceOf[AvroType]

      case P.Wildcard(label, _) => assignments(label).asInstanceOf[AvroType]
      case P.WildRecord(label, _) => assignments(label).asInstanceOf[AvroType]
    }

  // object prettyPrint extends Function2[Type, Boolean, String] {
  //   def apply(tpe: Type, html: Boolean): String = apply(tpe, html, mutable.Set[String]())

  //   private def apply(tpe: Type, html: Boolean, alreadyLabeled: mutable.Set[String]): String = tpe match {
  //     case _: AvroNull => "null"
  //     case _: AvroBoolean => "boolean"
  //     case _: AvroInt => "int"
  //     case _: AvroLong => "long"
  //     case _: AvroFloat => "float"
  //     case _: AvroDouble => "double"
  //     case _: AvroBytes => "bytes"
  //     case AvroFixed(size, _, _, _, _) => "fixed(%d)".format(size)
  //     case _: AvroString => "string"
  //     case AvroEnum(symbols, _, _, _, _) => "enum(%s)".format(symbols.mkString(" "))
  //     case AvroArray(items) => "array of " + prettyPrint(items, html, alreadyLabeled)
  //     case AvroMap(values) => "map of " + prettyPrint(values, html, alreadyLabeled)
  //     case AvroRecord(fields, _, _, _, _) => "record {%s}".format(
  //       fields map {case AvroField(name, avroType, _, _, _, _) => name + ": " + prettyPrint(avroType, html, alreadyLabeled)} mkString(", ")
  //     )
  //     case AvroUnion(types) => "union {%s}".format(types.map(prettyPrint(_, html, alreadyLabeled)).mkString(", "))
  //     case FcnType(params, ret) => "function {%s} \u2192 %s".format(
  //       params.map(prettyPrint(_, html, alreadyLabeled)).mkString(", "), prettyPrint(ret, html, alreadyLabeled)
  //     )
  //     case Wildcard(label, mustBe, structural) => {
  //       if (alreadyLabeled.contains(label))
  //         label
  //       else {
  //         alreadyLabeled.add(label)

  //         val struct =
  //           if (structural)
  //             " (structural)"
  //           else
  //             ""
  //         if (mustBe.size == 0)
  //           "any " + label
  //         else if (mustBe.size == 1)
  //           "any %s that is a %s%s".format(label, prettyPrint(mustBe.head, html, alreadyLabeled), struct)
  //         else
  //           "any %s that is in {%s}%s".format(label, mustBe.map(prettyPrint(_, html, alreadyLabeled)).mkString(", "), struct)
  //       }
  //     }
  //   }

  //   def apply(signature: Signature, html: Boolean): String = signature match {
  //     case x: Sig => doSig(x, html, mutable.Set[String]())
  //     case x: Sigs => doSigs(x, html)
  //   }

  //   private def doSigs(sig: Sigs, html: Boolean): String =
  //     sig.cases.map(doSig(_, html, mutable.Set[String]())).mkString("\n")

  //   private def doSig(sig: Sig, html: Boolean, alreadyLabeled: mutable.Set[String]): String =
  //     (sig.params map {case (n, t) => "%s: %s".format(n, prettyPrint(t, html, alreadyLabeled))} mkString(", ")) +
  //       " \u21d2 " + prettyPrint(sig.ret, html, alreadyLabeled) + (sig.constraintsDoc match {
  //         case Some(x) => "\n" + x.mkString("\n")
  //         case None => ""
  //       })
  // }
  }

}
