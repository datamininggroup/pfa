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

prefix = "s."

#################################################################### basic access

class Len(LibFcn):
    name = prefix + "len"
    sig = Sig([{"s": P.String()}], P.Int())
provide(Len)

class Substr(LibFcn):
    name = prefix + "substr"
    sig = Sig([{"s": P.String()}, {"start": P.Int()}, {"end": P.Int()}], P.String())
provide(Substr)

class SubstrTo(LibFcn):
    name = prefix + "substrto"
    sig = Sig([{"s": P.String()}, {"start": P.Int()}, {"end": P.Int()}, {"replacement": P.String()}], P.String())
provide(SubstrTo)

#################################################################### searching

class Contains(LibFcn):
    name = prefix + "contains"
    sig = Sig([{"haystack": P.String()}, {"needle": P.String()}], P.Boolean())
provide(Contains)

class Count(LibFcn):
    name = prefix + "count"
    sig = Sig([{"haystack": P.String()}, {"needle": P.String()}], P.Int())
provide(Count)

class Index(LibFcn):
    name = prefix + "index"
    sig = Sig([{"haystack": P.String()}, {"needle": P.String()}], P.Int())
provide(Index)

class RIndex(LibFcn):
    name = prefix + "rindex"
    sig = Sig([{"haystack": P.String()}, {"needle": P.String()}], P.Int())
provide(RIndex)

class StartsWith(LibFcn):
    name = prefix + "startswith"
    sig = Sig([{"haystack": P.String()}, {"needle": P.String()}], P.Boolean())
provide(StartsWith)

class EndsWith(LibFcn):
    name = prefix + "endswith"
    sig = Sig([{"haystack": P.String()}, {"needle": P.String()}], P.Boolean())
provide(EndsWith)

#################################################################### conversions to/from other types

class Join(LibFcn):
    name = prefix + "join"
    sig = Sig([{"array": P.Array(P.String())}, {"sep": P.String()}], P.String())
provide(Join)

class Split(LibFcn):
    name = prefix + "split"
    sig = Sig([{"s": P.String()}, {"sep": P.String()}], P.Array(P.String()))
provide(Split)

#################################################################### conversions to/from other strings

class Concat(LibFcn):
    name = prefix + "concat"
    sig = Sig([{"x": P.String()}, {"y": P.String()}], P.String())
provide(Concat)

class Repeat(LibFcn):
    name = prefix + "repeat"
    sig = Sig([{"s": P.String()}, {"n": P.Int()}], P.String())
provide(Repeat)

class Lower(LibFcn):
    name = prefix + "lower"
    sig = Sig([{"s": P.String()}], P.String())
provide(Lower)

class Upper(LibFcn):
    name = prefix + "upper"
    sig = Sig([{"s": P.String()}], P.String())
provide(Upper)

class LStrip(LibFcn):
    name = prefix + "lstrip"
    sig = Sig([{"s": P.String()}, {"chars": P.String()}], P.String())
provide(LStrip)

class RStrip(LibFcn):
    name = prefix + "rstrip"
    sig = Sig([{"s": P.String()}, {"chars": P.String()}], P.String())
provide(RStrip)

class Strip(LibFcn):
    name = prefix + "strip"
    sig = Sig([{"s": P.String()}, {"chars": P.String()}], P.String())
provide(Strip)

class ReplaceAll(LibFcn):
    name = prefix + "replaceall"
    sig = Sig([{"s": P.String()}, {"original": P.String()}, {"replacement": P.String()}], P.String())
provide(ReplaceAll)

class ReplaceFirst(LibFcn):
    name = prefix + "replacefirst"
    sig = Sig([{"s": P.String()}, {"original": P.String()}, {"replacement": P.String()}], P.String())
provide(ReplaceFirst)

class ReplaceLast(LibFcn):
    name = prefix + "replacelast"
    sig = Sig([{"s": P.String()}, {"original": P.String()}, {"replacement": P.String()}], P.String())
provide(ReplaceLast)

class Translate(LibFcn):
    name = prefix + "translate"
    sig = Sig([{"s": P.String()}, {"oldchars": P.String()}, {"newchars": P.String()}], P.String())
provide(Translate)
