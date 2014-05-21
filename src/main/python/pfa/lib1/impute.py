#!/usr/bin/env python

from pfa.fcn import Fcn
from pfa.fcn import LibFcn
from pfa.signature import Sig
from pfa.signature import Sigs
from pfa.datatype import *
import pfa.P as P

provides = {}
def provide(fcn):
    provides[fcn.name] = fcn

prefix = "impute."

class ErrorOnNull(LibFcn):
    name = prefix + "errorOnNull"
    sig = Sig([{"x": P.Union([P.Wildcard("A"), P.Null()])}], P.Wildcard("A"))
provide(ErrorOnNull)

class DefaultOnNull(LibFcn):
    name = prefix + "defaultOnNull"
    sig = Sig([{"x": P.Union([P.Wildcard("A"), P.Null()])}, {"default": P.Wildcard("A")}], P.Wildcard("A"))
provide(DefaultOnNull)
