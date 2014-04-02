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

prefix = "stat.sample."

#################################################################### 

class UpdateMean(LibFcn):
    name = prefix + "updateMean"
    sig = Sig([{"runningSum": P.WildRecord("A", {"sum_w": P.Double(), "sum_wx": P.Double()})}, {"w": P.Double()}, {"x": P.Double()}], P.Wildcard("A"))
provide(UpdateMean)

class Mean(LibFcn):
    name = prefix + "mean"
    sig = Sig([{"runningSum": P.WildRecord("A", {"sum_w": P.Double(), "sum_wx": P.Double()})}], P.Double())
provide(Mean)
