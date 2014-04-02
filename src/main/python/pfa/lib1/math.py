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

prefix = "m."

#################################################################### constants (0-arity side-effect free functions)

class Pi(LibFcn):
    name = prefix + "pi"
    sig = Sig([], P.Double())
provide(Pi)

class E(LibFcn):
    name = prefix + "e"
    sig = Sig([], P.Double())
provide(E)

#################################################################### functions (alphabetical order)

anyNumber = set([AvroInt(), AvroLong(), AvroFloat(), AvroDouble()])

class Abs(LibFcn):
    name = prefix + "abs"
    sig = Sig([{"x": P.Wildcard("A", anyNumber)}], P.Wildcard("A"))
provide(Abs)

class ACos(LibFcn):
    name = prefix + "acos"
    sig = Sig([{"x": P.Double()}], P.Double())
provide(ACos)

class ASin(LibFcn):
    name = prefix + "asin"
    sig = Sig([{"x": P.Double()}], P.Double())
provide(ASin)

class ATan(LibFcn):
    name = prefix + "atan"
    sig = Sig([{"x": P.Double()}], P.Double())
provide(ATan)

class ATan2(LibFcn):
    name = prefix + "atan2"
    sig = Sig([{"y": P.Double()}, {"x": P.Double()}], P.Double())
provide(ATan2)

class Ceil(LibFcn):
    name = prefix + "ceil"
    sig = Sig([{"x": P.Double()}], P.Double())
provide(Ceil)

class CopySign(LibFcn):
    name = prefix + "copysign"
    sig = Sig([{"mag": P.Wildcard("A", anyNumber)}, {"sign": P.Wildcard("A")}], P.Wildcard("A"))
provide(CopySign)

class Cos(LibFcn):
    name = prefix + "cos"
    sig = Sig([{"x": P.Double()}], P.Double())
provide(Cos)

class CosH(LibFcn):
    name = prefix + "cosh"
    sig = Sig([{"x": P.Double()}], P.Double())
provide(CosH)

class Exp(LibFcn):
    name = prefix + "exp"
    sig = Sig([{"x": P.Double()}], P.Double())
provide(Exp)

class ExpM1(LibFcn):
    name = prefix + "expm1"
    sig = Sig([{"x": P.Double()}], P.Double())
provide(ExpM1)

class Floor(LibFcn):
    name = prefix + "floor"
    sig = Sig([{"x": P.Double()}], P.Double())
provide(Floor)

class Hypot(LibFcn):
    name = prefix + "hypot"
    sig = Sig([{"x": P.Double()}, {"y": P.Double()}], P.Double())
provide(Hypot)

class Ln(LibFcn):
    name = prefix + "ln"
    sig = Sig([{"x": P.Double()}], P.Double())
provide(Ln)

class Log10(LibFcn):
    name = prefix + "log10"
    sig = Sig([{"x": P.Double()}], P.Double())
provide(Log10)

class Log(LibFcn):
    name = prefix + "log"
    sig = Sig([{"x": P.Double()}, {"base": P.Int()}], P.Double())
provide(Log)

class Ln1p(LibFcn):
    name = prefix + "ln1p"
    sig = Sig([{"x": P.Double()}], P.Double())
provide(Ln1p)

class Round(LibFcn):
    name = prefix + "round"
    sig = Sigs([Sig([{"x": P.Float()}], P.Int()),
                Sig([{"x": P.Double()}], P.Long())])
provide(Round)

class RInt(LibFcn):
    name = prefix + "rint"
    sig = Sig([{"x": P.Double()}], P.Double())
provide(RInt)

class Signum(LibFcn):
    name = prefix + "signum"
    sig = Sig([{"x": P.Double()}], P.Int())
provide(Signum)

class Sin(LibFcn):
    name = prefix + "sin"
    sig = Sig([{"x": P.Double()}], P.Double())
provide(Sin)

class SinH(LibFcn):
    name = prefix + "sinh"
    sig = Sig([{"x": P.Double()}], P.Double())
provide(SinH)

class Sqrt(LibFcn):
    name = prefix + "sqrt"
    sig = Sig([{"x": P.Double()}], P.Double())
provide(Sqrt)

class Tan(LibFcn):
    name = prefix + "tan"
    sig = Sig([{"x": P.Double()}], P.Double())
provide(Tan)

class TanH(LibFcn):
    name = prefix + "tanh"
    sig = Sig([{"x": P.Double()}], P.Double())
provide(TanH)
