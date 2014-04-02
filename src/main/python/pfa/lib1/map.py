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

prefix = "map."

#################################################################### basic access
