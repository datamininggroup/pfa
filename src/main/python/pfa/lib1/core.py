#!/usr/bin/env python

from pfa.fcn import Fcn
from pfa.fcn import LibFcn
from pfa.signature import Sig
from pfa.signature import Sigs
from pfa.types import *
import pfa.P as P

provides = {}
def provide(fcn):
    provides[fcn.name] = fcn

anyNumber = set([AvroInt(), AvroLong(), AvroFloat(), AvroDouble()])

#################################################################### basic arithmetic

class Plus(LibFcn):
    name = "+"
    sig = Sig([{"x": P.Wildcard("A", anyNumber)}, {"y" : P.Wildcard("A")}], P.Wildcard("A"))
provide(Plus())

class Minus(LibFcn):
    name = "-"
    sig = Sig([{"x": P.Wildcard("A", anyNumber)}, {"y": P.Wildcard("A")}], P.Wildcard("A"))
provide(Minus())

class Times(LibFcn):
    name = "*"
    sig = Sig([{"x": P.Wildcard("A", anyNumber)}, {"y": P.Wildcard("A")}], P.Wildcard("A"))
provide(Times())

class Divide(LibFcn):
    name = "/"
    sig = Sig([{"x": P.Double()}, {"y": P.Double()}], P.Double())
provide(Divide())

class FloorDivide(LibFcn):
    name = "//"
    sig = Sig([{"x": P.Wildcard("A", set([AvroInt(), AvroLong()]))}, {"y": P.Wildcard("A")}], P.Wildcard("A"))
provide(FloorDivide())

class Negative(LibFcn):
    name = "u-"
    sig = Sig([{"x": P.Wildcard("A", anyNumber)}], P.Wildcard("A"))
provide(Negative())

class Modulo(LibFcn):
    name = "%"
    sig = Sig([{"k": P.Wildcard("A", anyNumber)}, {"n": P.Wildcard("A")}], P.Wildcard("A"))
provide(Modulo())

class Remainder(LibFcn):
    name = "%%"
    sig = Sig([{"k": P.Wildcard("A", anyNumber)}, {"n": P.Wildcard("A")}], P.Wildcard("A"))
provide(Remainder())

class Pow(LibFcn):
    name = "**"
    sig = Sig([{"x": P.Wildcard("A", anyNumber)}, {"y": P.Wildcard("A")}], P.Wildcard("A"))
provide(Pow())

#################################################################### generic comparison operators

class Comparison(LibFcn):
    name = "cmp"
    sig = Sig([{"x": P.Wildcard("A")}, {"y": P.Wildcard("A")}], P.Int())
provide(Comparison())

class Equal(LibFcn):
    name = "=="
    sig = Sig([{"x": P.Wildcard("A")}, {"y": P.Wildcard("A")}], P.Boolean)
provide(Equal())

class GreaterOrEqual(LibFcn):
    name = ">="
    sig = Sig([{"x": P.Wildcard("A")}, {"y": P.Wildcard("A")}], P.Boolean)
provide(GreaterOrEqual())

class GreaterThan(LibFcn):
    name = ">"
    sig = Sig([{"x": P.Wildcard("A")}, {"y": P.Wildcard("A")}], P.Boolean)
provide(GreaterThan())

class NotEqual(LibFcn):
    name = "!="
    sig = Sig([{"x": P.Wildcard("A")}, {"y": P.Wildcard("A")}], P.Boolean)
provide(NotEqual())

class LessThan(LibFcn):
    name = "<"
    sig = Sig([{"x": P.Wildcard("A")}, {"y": P.Wildcard("A")}], P.Boolean)
provide(LessThan())

class LessOrEqual(LibFcn):
    name = "<="
    sig = Sig([{"x": P.Wildcard("A")}, {"y": P.Wildcard("A")}], P.Boolean)
provide(LessOrEqual())

#################################################################### max and min

class Max(LibFcn):
    name = "max"
    sig = Sig([{"x": P.Wildcard("A")}, {"y": P.Wildcard("A")}], P.Wildcard("A"))
provide(Max())

class Min(LibFcn):
    name = "min"
    sig = Sig([{"x": P.Wildcard("A")}, {"y": P.Wildcard("A")}], P.Wildcard("A"))
provide(Min())

#################################################################### logical operators

class LogicalAnd(LibFcn):
    name = "and"
    sig = Sig([{"x": P.Boolean()}, {"y": P.Boolean()}], P.Boolean())
provide(LogicalAnd())

class LogicalOr(LibFcn):
    name = "or"
    sig = Sig([{"x": P.Boolean()}, {"y": P.Boolean()}], P.Boolean())
provide(LogicalOr())

class LogicalXOr(LibFcn):
    name = "xor"
    sig = Sig([{"x": P.Boolean()}, {"y": P.Boolean()}], P.Boolean())
provide(LogicalXOr())

class LogicalNot(LibFcn):
    name = "not"
    sig = Sig([{"x": P.Boolean()}], P.Boolean())
provide(LogicalNot())

#################################################################### bitwise arithmetic

class BitwiseAnd(LibFcn):
    name = "&"
    sig = Sigs([Sig([{"x": P.Int()}, {"y": P.Int()}], P.Int()),
                Sig([{"x": P.Long()}, {"y": P.Long()}], P.Long())])

provide(BitwiseAnd())

class BitwiseOr(LibFcn):
    name = "|"
    sig = Sigs([Sig([{"x": P.Int()}, {"y": P.Int()}], P.Int()),
                Sig([{"x": P.Long()}, {"y": P.Long()}], P.Long())])

provide(BitwiseOr())

class BitwiseXOr(LibFcn):
    name = "^"
    sig = Sigs([Sig([{"x": P.Int()}, {"y": P.Int()}], P.Int()),
                Sig([{"x": P.Long()}, {"y": P.Long()}], P.Long())])

provide(BitwiseXOr())

class BitwiseNot(LibFcn):
    name = "~"
    sig = Sigs([Sig([{"x": P.Int()}], P.Int()),
                Sig([{"x": P.Long()}], P.Long())])

provide(BitwiseNot())


