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

prefix = "a."

anyNumber = set([AvroInt(), AvroLong(), AvroFloat(), AvroDouble()])

#################################################################### basic access

class Len(LibFcn):
    name = prefix + "len"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}], P.Int())
provide(Len)

class Subseq(LibFcn):
    name = prefix + "subseq"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"start": P.Int()}, {"end": P.Int()}], P.Array(P.Wildcard("A")))
provide(Subseq)

class SubseqTo(LibFcn):
    name = prefix + "subseqto"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"start": P.Int()}, {"end": P.Int()}, {"replacement": P.Array(P.Wildcard("A"))}], P.Array(P.Wildcard("A")))
provide(SubseqTo)

#################################################################### searching

class Contains(LibFcn):
    name = prefix + "contains"
    sig = Sigs([Sig([{"haystack": P.Array(P.Wildcard("A"))}, {"needle": P.Array(P.Wildcard("A"))}], P.Boolean()),
                Sig([{"haystack": P.Array(P.Wildcard("A"))}, {"needle": P.Wildcard("A")}], P.Boolean())])
provide(Contains)

class Count(LibFcn):
    name = prefix + "count"
    sig = Sigs([Sig([{"haystack": P.Array(P.Wildcard("A"))}, {"needle": P.Array(P.Wildcard("A"))}], P.Int()),
                Sig([{"haystack": P.Array(P.Wildcard("A"))}, {"needle": P.Wildcard("A")}], P.Int()),
                Sig([{"a": P.Array(P.Wildcard("A"))}, {"predicate": P.Fcn([P.Wildcard("A")], P.Boolean())}], P.Int())])
provide(Count)

class Index(LibFcn):
    name = prefix + "index"
    sig = Sigs([Sig([{"haystack": P.Array(P.Wildcard("A"))}, {"needle": P.Array(P.Wildcard("A"))}], P.Int()),
                Sig([{"haystack": P.Array(P.Wildcard("A"))}, {"needle": P.Wildcard("A")}], P.Int())])
provide(Index)

class RIndex(LibFcn):
    name = prefix + "rindex"
    sig = Sigs([Sig([{"haystack": P.Array(P.Wildcard("A"))}, {"needle": P.Array(P.Wildcard("A"))}], P.Int()),
                Sig([{"haystack": P.Array(P.Wildcard("A"))}, {"needle": P.Wildcard("A")}], P.Int())])
provide(RIndex)

class StartsWith(LibFcn):
    name = prefix + "startswith"
    sig = Sigs([Sig([{"haystack": P.Array(P.Wildcard("A"))}, {"needle": P.Array(P.Wildcard("A"))}], P.Boolean()),
                Sig([{"haystack": P.Array(P.Wildcard("A"))}, {"needle": P.Wildcard("A")}], P.Boolean())])
provide(StartsWith)

class EndsWith(LibFcn):
    name = prefix + "endswith"
    sig = Sigs([Sig([{"haystack": P.Array(P.Wildcard("A"))}, {"needle": P.Array(P.Wildcard("A"))}], P.Boolean()),
                Sig([{"haystack": P.Array(P.Wildcard("A"))}, {"needle": P.Wildcard("A")}], P.Boolean())])
provide(EndsWith)

#################################################################### manipulation

class Concat(LibFcn):
    name = prefix + "concat"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"b": P.Array(P.Wildcard("A"))}], P.Array(P.Wildcard("A")))
provide(Concat)

class Append(LibFcn):
    name = prefix + "append"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"item": P.Wildcard("A")}], P.Array(P.Wildcard("A")))
provide(Append)

class Insert(LibFcn):
    name = prefix + "insert"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"index": P.Int()}, {"item": P.Wildcard("A")}], P.Array(P.Wildcard("A")))
provide(Insert)

class Replace(LibFcn):
    name = prefix + "replace"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"index": P.Int()}, {"item": P.Wildcard("A")}], P.Array(P.Wildcard("A")))
provide(Replace)

class Remove(LibFcn):
    name = prefix + "remove"
    sig = Sigs([Sig([{"a": P.Array(P.Wildcard("A"))}, {"start": P.Int()}, {"end": P.Int()}], P.Array(P.Wildcard("A"))),
                Sig([{"a": P.Array(P.Wildcard("A"))}, {"index": P.Int()}], P.Array(P.Wildcard("A")))])
provide(Remove)

#################################################################### reordering

class Sort(LibFcn):
    name = prefix + "sort"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}], P.Array(P.Wildcard("A")))
provide(Sort)

class SortLT(LibFcn):
    name = prefix + "sortLT"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"lessThan": P.Fcn([P.Wildcard("A"), P.Wildcard("A")], P.Boolean())}], P.Array(P.Wildcard("A")))
provide(SortLT)

class Shuffle(LibFcn):
    name = prefix + "shuffle"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}], P.Array(P.Wildcard("A")))
provide(Shuffle)

class Reverse(LibFcn):
    name = prefix + "reverse"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}], P.Array(P.Wildcard("A")))
provide(Reverse)

#################################################################### extreme values

class Max(LibFcn):
    name = prefix + "max"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}], P.Wildcard("A"))
provide(Max)

class Min(LibFcn):
    name = prefix + "min"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}], P.Wildcard("A"))
provide(Min)

class MaxLT(LibFcn):
    name = prefix + "maxLT"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"lessThan": P.Fcn([P.Wildcard("A"), P.Wildcard("A")], P.Boolean())}], P.Wildcard("A"))
provide(MaxLT)

class MinLT(LibFcn):
    name = prefix + "minLT"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"lessThan": P.Fcn([P.Wildcard("A"), P.Wildcard("A")], P.Boolean())}], P.Wildcard("A"))
provide(MinLT)

class MaxN(LibFcn):
    name = prefix + "maxN"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"n": P.Int()}], P.Array(P.Wildcard("A")))
provide(MaxN)

class MinN(LibFcn):
    name = prefix + "minN"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"n": P.Int()}], P.Array(P.Wildcard("A")))
provide(MinN)

class MaxNLT(LibFcn):
    name = prefix + "maxNLT"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"n": P.Int()}, {"lessThan": P.Fcn([P.Wildcard("A"), P.Wildcard("A")], P.Boolean())}], P.Array(P.Wildcard("A")))
provide(MaxNLT)

class MinNLT(LibFcn):
    name = prefix + "minNLT"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"n": P.Int()}, {"lessThan": P.Fcn([P.Wildcard("A"), P.Wildcard("A")], P.Boolean())}], P.Array(P.Wildcard("A")))
provide(MinNLT)

class Argmax(LibFcn):
    name = prefix + "argmax"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}], P.Int())
provide(Argmax)

class Argmin(LibFcn):
    name = prefix + "argmin"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}], P.Int())
provide(Argmin)

class ArgmaxLT(LibFcn):
    name = prefix + "argmaxLT"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"lessThan": P.Fcn([P.Wildcard("A"), P.Wildcard("A")], P.Boolean())}], P.Int())
provide(ArgmaxLT)

class ArgminLT(LibFcn):
    name = prefix + "argminLT"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"lessThan": P.Fcn([P.Wildcard("A"), P.Wildcard("A")], P.Boolean())}], P.Int())
provide(ArgminLT)

class ArgmaxN(LibFcn):
    name = prefix + "argmaxN"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"n": P.Int()}], P.Array(P.Int()))
provide(ArgmaxN)

class ArgminN(LibFcn):
    name = prefix + "argminN"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"n": P.Int()}], P.Array(P.Int()))
provide(ArgminN)

class ArgmaxNLT(LibFcn):
    name = prefix + "argmaxNLT"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"n": P.Int()}, {"lessThan": P.Fcn([P.Wildcard("A"), P.Wildcard("A")], P.Boolean())}], P.Array(P.Int()))
provide(ArgmaxNLT)

class ArgminNLT(LibFcn):
    name = prefix + "argminNLT"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"n": P.Int()}, {"lessThan": P.Fcn([P.Wildcard("A"), P.Wildcard("A")], P.Boolean())}], P.Array(P.Int()))
provide(ArgminNLT)

#################################################################### numerical

class Sum(LibFcn):
    name = prefix + "sum"
    sig = Sig([{"a": P.Array(P.Wildcard("A", oneOf = anyNumber))}], P.Wildcard("A"))
provide(Sum)

class Product(LibFcn):
    name = prefix + "product"
    sig = Sig([{"a": P.Array(P.Wildcard("A", oneOf = anyNumber))}], P.Wildcard("A"))
provide(Product)

class Lnsum(LibFcn):
    name = prefix + "lnsum"
    sig = Sig([{"a": P.Array(P.Double())}], P.Double())
provide(Lnsum)

class Mean(LibFcn):
    name = prefix + "mean"
    sig = Sig([{"a": P.Array(P.Double())}], P.Double())
provide(Mean)

class GeoMean(LibFcn):
    name = prefix + "geomean"
    sig = Sig([{"a": P.Array(P.Double())}], P.Double())
provide(GeoMean)

class Median(LibFcn):
    name = prefix + "median"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}], P.Wildcard("A"))
provide(Median)

class Mode(LibFcn):
    name = prefix + "mode"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}], P.Wildcard("A"))
provide(Mode)

#################################################################### set or set-like functions

class Distinct(LibFcn):
    name = prefix + "distinct"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}], P.Array(P.Wildcard("A")))
provide(Distinct)

class SetEq(LibFcn):
    name = prefix + "seteq"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"b": P.Array(P.Wildcard("A"))}], P.Boolean())
provide(SetEq)

class Union(LibFcn):
    name = prefix + "union"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"b": P.Array(P.Wildcard("A"))}], P.Array(P.Wildcard("A")))
provide(Union)

class Intersect(LibFcn):
    name = prefix + "intersect"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"b": P.Array(P.Wildcard("A"))}], P.Array(P.Wildcard("A")))
provide(Intersect)

class Diff(LibFcn):
    name = prefix + "diff"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"b": P.Array(P.Wildcard("A"))}], P.Array(P.Wildcard("A")))
provide(Diff)

class SymDiff(LibFcn):
    name = prefix + "symdiff"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"b": P.Array(P.Wildcard("A"))}], P.Array(P.Wildcard("A")))
provide(SymDiff)

class Subset(LibFcn):
    name = prefix + "subset"
    sig = Sig([{"little": P.Array(P.Wildcard("A"))}, {"big": P.Array(P.Wildcard("A"))}], P.Boolean())
provide(Subset)

class Disjoint(LibFcn):
    name = prefix + "disjoint"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"b": P.Array(P.Wildcard("A"))}], P.Boolean())
provide(Disjoint)

#################################################################### functional programming

class MapApply(LibFcn):
    name = prefix + "map"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"fcn": P.Fcn([P.Wildcard("A")], P.Wildcard("B"))}], P.Array(P.Wildcard("B")))
provide(MapApply)

class Filter(LibFcn):
    name = prefix + "filter"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"fcn": P.Fcn([P.Wildcard("A")], P.Boolean())}], P.Array(P.Wildcard("A")))
provide(Filter)

class FilterMap(LibFcn):
    name = prefix + "filtermap"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"fcn": P.Fcn([P.Wildcard("A")], P.Union([P.Wildcard("B"), P.Null()]))}], P.Array(P.Wildcard("B")))
provide(FilterMap)

class FlatMap(LibFcn):
    name = prefix + "flatmap"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"fcn": P.Fcn([P.Wildcard("A")], P.Array(P.Wildcard("B")))}], P.Array(P.Wildcard("B")))
provide(FlatMap)

class Reduce(LibFcn):
    name = prefix + "reduce"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"fcn": P.Fcn([P.Wildcard("A"), P.Wildcard("A")], P.Wildcard("A"))}], P.Wildcard("A"))
provide(Reduce)

class ReduceRight(LibFcn):
    name = prefix + "reduceright"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"fcn": P.Fcn([P.Wildcard("A"), P.Wildcard("A")], P.Wildcard("A"))}], P.Wildcard("A"))
provide(ReduceRight)

class Fold(LibFcn):
    name = prefix + "fold"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"zero": P.Wildcard("B")}, {"fcn": P.Fcn([P.Wildcard("B"), P.Wildcard("A")], P.Wildcard("B"))}], P.Wildcard("B"))
provide(Fold)

class FoldRight(LibFcn):
    name = prefix + "foldright"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"zero": P.Wildcard("B")}, {"fcn": P.Fcn([P.Wildcard("B"), P.Wildcard("A")], P.Wildcard("B"))}], P.Wildcard("B"))
provide(FoldRight)

class TakeWhile(LibFcn):
    name = prefix + "takeWhile"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"fcn": P.Fcn([P.Wildcard("A")], P.Boolean())}], P.Array(P.Wildcard("A")))
provide(TakeWhile)

class DropWhile(LibFcn):
    name = prefix + "dropWhile"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"fcn": P.Fcn([P.Wildcard("A")], P.Boolean())}], P.Array(P.Wildcard("A")))
provide(DropWhile)

#################################################################### functional tests

class Any(LibFcn):
    name = prefix + "any"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"fcn": P.Fcn([P.Wildcard("A")], P.Boolean())}], P.Boolean())
provide(Any)

class All(LibFcn):
    name = prefix + "all"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"fcn": P.Fcn([P.Wildcard("A")], P.Boolean())}], P.Boolean())
provide(All)

class Corresponds(LibFcn):
    name = prefix + "corresponds"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"b": P.Array(P.Wildcard("B"))}, {"fcn": P.Fcn([P.Wildcard("A"), P.Wildcard("B")], P.Boolean())}], P.Boolean())
provide(Corresponds)

#################################################################### restructuring

class SlidingWindow(LibFcn):
    name = prefix + "slidingWindow"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"size": P.Int()}, {"step": P.Int()}, {"allowIncomplete": P.Boolean()}], P.Array(P.Array(P.Wildcard("A"))))
provide(SlidingWindow)

class Combinations(LibFcn):
    name = prefix + "combinations"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"size": P.Int()}], P.Array(P.Array(P.Wildcard("A"))))
provide(Combinations)

class Permutations(LibFcn):
    name = prefix + "permutations"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}], P.Array(P.Array(P.Wildcard("A"))))
provide(Permutations)

class Flatten(LibFcn):
    name = prefix + "flatten"
    sig = Sig([{"a": P.Array(P.Array(P.Wildcard("A")))}], P.Array(P.Wildcard("A")))
provide(Flatten)

class GroupBy(LibFcn):
    name = prefix + "groupby"
    sig = Sig([{"a": P.Array(P.Wildcard("A"))}, {"fcn": P.Fcn([P.Wildcard("A")], P.String())}], P.Map(P.Array(P.Wildcard("A"))))
provide(GroupBy)
