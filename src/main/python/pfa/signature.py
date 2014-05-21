#!/usr/bin/env python

import pfa.P as P
from pfa.datatype import Type
from pfa.datatype import FcnType
from pfa.datatype import AvroType
from pfa.datatype import AvroCompiled
from pfa.datatype import AvroNull
from pfa.datatype import AvroBoolean
from pfa.datatype import AvroInt
from pfa.datatype import AvroLong
from pfa.datatype import AvroFloat
from pfa.datatype import AvroDouble
from pfa.datatype import AvroBytes
from pfa.datatype import AvroFixed
from pfa.datatype import AvroString
from pfa.datatype import AvroEnum
from pfa.datatype import AvroArray
from pfa.datatype import AvroMap
from pfa.datatype import AvroRecord
from pfa.datatype import AvroField
from pfa.datatype import AvroUnion

class IncompatibleTypes(Exception): pass

class LabelData(object):
    @staticmethod
    def distinctTypes(candidates, out = None):
        if out is None:
            out = []
        for candidate in candidates:
            if isinstance(candidate, AvroUnion):
                out = LabelData.distinctTypes(candidate.types, out)
            elif any(y.accepts(candidate) for y in out):
                pass
            else:
                i = 0
                for y in out:
                    if candidate.accepts(y): break
                    i += 1
                if i == len(out):
                    out.append(candidate)
                else:
                    out[i] = candidate
        return out

    @staticmethod
    def broadestType(candidates):
        if len(candidates) == 0:
            return ValueError("empty list of types")

        elif all(isinstance(x, AvroNull) for x in candidates):
            return candidates[0]
        elif all(isinstance(x, AvroBoolean) for x in candidates):
            return candidates[0]

        elif all(isinstance(x, AvroInt) for x in candidates):
            return AvroInt()
        elif all(isinstance(x, AvroInt) or isinstance(x, AvroLong) for x in candidates):
            return AvroLong()
        elif all(isinstance(x, AvroInt) or isinstance(x, AvroLong) or isinstance(x, AvroFloat) for x in candidates):
            return AvroFloat()
        elif all(isinstance(x, AvroInt) or isinstance(x, AvroLong) or isinstance(x, AvroFloat) or isinstance(x, AvroDouble) for x in candidates):
            return AvroDouble()

        elif all(isinstance(x, AvroBytes) for x in candidates):
            return candidates[0]
        elif all(isinstance(x, AvroString) for x in candidates):
            return candidates[0]

        elif all(isinstance(x, AvroArray) for x in candidates):
            return AvroArray(P.mustBeAvro(LabelData.broadestType([x.items for x in candidates])))

        elif all(isinstance(x, AvroMap) for x in candidates):
            return AvroMap(P.mustBeAvro(LabelData.broadestType([x.values for x in candidates])))

        elif all(isinstance(x, AvroFixed) for x in candidates):
            fullName = candidates[0].fullName
            if all(x.fullName == fullName for x in candidates[1:]):
                return candidates[0]
            else:
                raise IncompatibleTypes("incompatible fixed types: " + " ".join(map(repr, candidates)))

        elif all(isinstance(x, AvroEnum) for x in candidates):
            fullName = candidates[0].fullName
            if all(x.fullName == fullName for x in candidates[1:]):
                return candidates[0]
            else:
                raise IncompatibleTypes("incompatible enum types: " + " ".join(map(repr, candidates)))

        elif all(isinstance(x, AvroRecord) for x in candidates):
            fullName = candidates[0].fullName
            if all(x.fullName == fullName for x in candidates[1:]):
                return candidates[0]
            else:
                raise IncompatibleTypes("incompatible record types: " + " ".join(map(repr, candidates)))

        elif all(isinstance(x, FcnType) for x in candidates):
            params = candidates[0].params
            ret = candidates[0].ret

            if all(x.params == params and x.ret == ret for x in candidates[1:]):
                return candidates[0]
            else:
                raise IncompatibleTypes("incompatible function types: " + " ".join(map(repr, candidates)))

        else:
            types = LabelData.distinctTypes(candidates)
            types = [P.mustBeAvro(x) for x in types]

            countFixed = 0
            countEnum = 0
            for t in types:
                if isinstance(t, AvroFixed):
                    countFixed += 1
                if isinstance(t, AvroEnum):
                    countEnum += 1

            if countFixed > 1:
                raise IncompatibleTypes("incompatible fixed types")
            if countEnum > 1:
                raise IncompatibleTypes("incompatible enum types")

            return AvroUnion(types)

    def __init__(self):
        self.members = []

    def add(self, t):
        self.members.append(t)

    def determineAssignment(self):
        return LabelData.broadestType(self.members)

class Signature(object):
    def accepts(self, args):
        raise NotImplementedError

class Sigs(Signature):
    def __init__(self, cases):
        self.cases = cases

    def accepts(self, args):
        for case in cases:
            if case.accepts(args):
                return case
        return None

class Sig(Signature):
    def __init__(self, params, ret):
        self.params = params
        self.ret = ret

    def accepts(self, args):
        labelData = {}
        if len(self.params) == len(args) and all(self.check(p.values()[0], a, labelData, False, False) for p, a in zip(self.params, args)):
            try:
                assignments = dict((l, ld.determineAssignment()) for l, ld in labelData.items())
                assignedParams = [self.assign(p.values()[0], a, assignments) for p, a in zip(self.params, args)]
                assignedRet = self.assignRet(self.ret, assignments)
                return (assignedParams, assignedRet)

            except IncompatibleTypes:
                return None
        else:
            return None

    def check(self, pat, arg, labelData, strict, reversed):
        if isinstance(pat, P.Null) and isinstance(arg, AvroNull):
            return True
        elif isinstance(pat, P.Boolean) and isinstance(arg, AvroBoolean):
            return True

        elif isinstance(pat, P.Int) and isinstance(arg, AvroInt):
            return True
        elif isinstance(pat, P.Long) and isinstance(arg, AvroLong):
            return True
        elif isinstance(pat, P.Float) and isinstance(arg, AvroFloat):
            return True
        elif isinstance(pat, P.Double) and isinstance(arg, AvroDouble):
            return True

        elif not strict and not reversed and \
                 isinstance(pat, P.Long) and (isinstance(arg, AvroInt) or isinstance(arg, AvroLong)):
            return True
        elif not strict and not reversed and \
                 isinstance(pat, P.Float) and (isinstance(arg, AvroInt) or isinstance(arg, AvroLong) or isinstance(arg, AvroFloat)):
            return True
        elif not strict and not reversed and \
                 isinstance(pat, P.Double) and (isinstance(arg, AvroInt) or isinstance(arg, AvroLong) or isinstance(arg, AvroFloat) or isinstance(arg, AvroDouble)):
            return True

        elif not strict and reversed and \
                 (isinstance(pat, P.Int) or isinstance(pat, P.Long)) and isinstance(arg, AvroLong):
            return True
        elif not strict and reversed and \
                 (isinstance(pat, P.Int) or isinstance(pat, P.Long) or isinstance(pat, P.Float)) and isinstance(arg, AvroFloat):
            return True
        elif not strict and reversed and \
                 (isinstance(pat, P.Int) or isinstance(pat, P.Long) or isinstance(pat, P.Float) or isinstance(pat, P.Double)) and isinstance(arg, AvroDouble):
            return True

        elif isinstance(pat, P.Bytes) and isinstance(arg, AvroBytes):
            return True
        elif isinstance(pat, P.String) and isinstance(arg, AvroString):
            return True

        elif isinstance(pat, P.Array) and isinstance(arg, AvroArray):
            return self.check(pat.items, arg.items, labelData, strict, reversed)
        elif isinstance(pat, P.Map) and isinstance(arg, AvroMap):
            return self.check(pat.values, arg.values, labelData, strict, reversed)
        elif isinstance(pat, P.Union) and isinstance(arg, AvroUnion):
            available = dict((i, x) for i, x in enumerate(pat.types))
            for a in arg.types:
                found = False
                for i, p in available.items():
                    if self.check(p, a, labelData, True, reversed):
                        del available[i]
                        found = True
                        break
                if not found:
                    return False
            return True

        elif isinstance(pat, P.Fixed) and isinstance(arg, AvroFixed):
            if pat.fullName is not None:
                return pat.fullName == arg.fullName
            else:
                return pat.size == arg.size

        elif isinstance(pat, P.Enum) and isinstance(arg, AvroEnum):
            if pat.fullName is not None:
                return pat.fullName == arg.fullName
            else:
                return pat.symbols == arg.symbols

        elif isinstance(pat, P.Record) and isinstance(arg, AvroRecord):
            if pat.fullName is not None:
                return pat.fullName == arg.fullName
            else:
                amap = dict((x.name, x) for x in arg.fields)

                if set(pat.fields.keys()) == set(amap.keys()):
                    return all(self.check(pat.fields[k], amap[k].avroType, labelData, True, reversed) for k in pat.fields.keys())
                else:
                    return False

        elif isinstance(pat, P.Fcn) and isinstance(arg, FcnType):
            return all(self.check(p, a, labelData, strict, True) for p, a in zip(pat.params, arg.params)) and \
                   self.check(pat.ret, arg.ret, labelData, strict, False)

        elif isinstance(pat, P.Wildcard):
            if pat.oneOf is None or arg in pat.oneOf:
                if not pat.label in labelData:
                    labelData[pat.label] = LabelData()
                labelData[pat.label].add(arg)
                return True
            else:
                return False

        elif isinstance(pat, P.WildRecord) and isinstance(arg, AvroRecord):
            if not pat.label in labelData:
                labelData[pat.label] = LabelData()
            labelData[pat.label].add(arg)

            amap = dict((x.name, x) for x in arg.fields)

            if set(pat.minimalFields.keys()).issubset(set(amap.keys())):
                return all(self.check(pt, amap[pn].avroType, labelData, True, reversed) for pn, pt in pat.minimalFields.items())
            else:
                return False

        else:
            return False

    def assign(self, pat, arg, assignments):
        if isinstance(pat, P.Null) and isinstance(arg, AvroNull):
            return arg
        elif isinstance(pat, P.Boolean) and isinstance(arg, AvroBoolean):
            return arg

        elif isinstance(pat, P.Int) and isinstance(arg, AvroInt):
            return AvroInt()
        elif isinstance(pat, P.Long) and (isinstance(arg, AvroInt) or isinstance(arg, AvroLong)):
            return AvroLong()
        elif isinstance(pat, P.Float) and (isinstance(arg, AvroInt) or isinstance(arg, AvroLong) or isinstance(arg, AvroFloat)):
            return AvroFloat()
        elif isinstance(pat, P.Double) and (isinstance(arg, AvroInt) or isinstance(arg, AvroLong) or isinstance(arg, AvroFloat) or isinstance(arg, AvroDouble)):
            return AvroDouble()

        elif isinstance(pat, P.Bytes) and isinstance(arg, AvroBytes):
            return arg
        elif isinstance(pat, P.String) and isinstance(arg, AvroString):
            return arg

        elif isinstance(pat, P.Array) and isinstance(arg, AvroArray):
            return AvroArray(P.mustBeAvro(self.assign(pat.items, arg.items, assignments)))
        elif isinstance(pat, P.Map) and isinstance(arg, AvroMap):
            return AvroMap(P.mustBeAvro(self.assign(pat.values, arg.values, assignments)))
        elif isinstance(pat, P.Union) and isinstance(arg, AvroUnion):
            return arg

        elif isinstance(pat, P.Fixed) and isinstance(arg, AvroFixed):
            return arg
        elif isinstance(pat, P.Enum) and isinstance(arg, AvroEnum):
            return arg
        elif isinstance(pat, P.Record) and isinstance(arg, AvroRecord):
            return arg

        elif isinstance(pat, P.Fcn) and isinstance(arg, FcnType):
            return arg

        elif isinstance(pat, P.Wildcard):
            return assignments[pat.label]
        elif isinstance(pat, P.WildRecord):
            return assignments[pat.label]

        else:
            raise Exception

    def assignRet(self, pat, assignments):
        if isinstance(pat, P.Null):
            return AvroNull()
        elif isinstance(pat, P.Boolean):
            return AvroBoolean()
        elif isinstance(pat, P.Int):
            return AvroInt()
        elif isinstance(pat, P.Long):
            return AvroLong()
        elif isinstance(pat, P.Float):
            return AvroFloat()
        elif isinstance(pat, P.Double):
            return AvroDouble()
        elif isinstance(pat, P.Bytes):
            return AvroBytes()
        elif isinstance(pat, P.String):
            return AvroString()

        elif isinstance(pat, P.Array):
            return AvroArray(self.assignRet(pat.items, assignments))
        elif isinstance(pat, P.Map):
            return AvroMap(self.assignRet(pat.values, assignments))
        elif isinstance(pat, P.Union):
            return AvroUnion([self.assignRet(x, assignments) for x in pat.types])

        elif isinstance(pat, P.Fixed):
            return P.toType(pat)
        elif isinstance(pat, P.Enum):
            return P.toType(pat)
        elif isinstance(pat, P.Record):
            return P.toType(pat)
        elif isinstance(pat, P.Fcn):
            return P.toType(pat)

        elif isinstance(pat, P.Wildcard):
            return assignments[pat.label]
        elif isinstance(pat, P.WildRecord):
            return assignments[pat.label]

        else:
            raise Exception
