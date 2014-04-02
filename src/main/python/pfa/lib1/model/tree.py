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

prefix = "model.tree."

#################################################################### 

class SimpleWalk(LibFcn):
    name = prefix + "simpleWalk"
    sig = Sig([{"datum": P.WildRecord("D", {})},
               {"treeNode": P.WildRecord("T", {"field": P.String(),
                                               "operator": P.String(),
                                               "value": P.Wildcard("V"),
                                               "pass": P.Union([P.WildRecord("T", {}), P.Wildcard("S")]),
                                               "fail": P.Union([P.WildRecord("T", {}), P.Wildcard("S")])})}],
              P.Wildcard("S"))
provide(SimpleWalk)

class PredicateWalk(LibFcn):
    name = prefix + "predicateWalk"
    sig = Sig([{"datum": P.WildRecord("D", {})},
               {"treeNode": P.WildRecord("T", {"pass": P.Union([P.WildRecord("T", {}), P.Wildcard("S")]),
                                               "fail": P.Union([P.WildRecord("T", {}), P.Wildcard("S")])})}],
              P.Wildcard("S"))
provide(PredicateWalk)
