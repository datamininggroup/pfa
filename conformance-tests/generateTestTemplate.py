#!/usr/bin/env python

import math
import json
import xml.etree.ElementTree
import re
from collections import OrderedDict as odict
import codecs
import sys
import base64

class Signature(object):
    def __init__(self, sig):
        self.parameters = [Parameter(x) for x in sig.findall("./par")]
        self.ret = pattern(sig.find("./ret"))
    def __repr__(self):
        return "Signature([" + ", ".join(repr(x) for x in self.parameters) + "], " + repr(self.ret) + ")"

    def generateNormal(self, considered, fcnName, valueOverrides, nondeterministic):
        labels = odict()
        for x in self.parameters:
            x.getlabels(labels)
        self.ret.getlabels(labels)

        pfas = []
        if len(labels) == 0:
            nameLookup = {}
            types = odict()
            for x in self.parameters:
                types[x.name] = self.resolve(x.pattern, {}, nameLookup)
            output = self.resolve(self.ret, {}, nameLookup)

            signature = tuple([(k, self.makeHashable(v)) for k, v in types.items()] + [(None, self.makeHashable(output))])
            if signature not in considered:
                pfas.append(self.renderAsPFA(fcnName, valueOverrides, nameLookup, types, output, nondeterministic))
                considered.add(signature)

        else:
            for assignment in self.assignments(labels):
                # assign all names (in place)
                nameCounters = {"record": 1, "enum": 1, "fixed": 1}
                for x in self.parameters:
                    x.pattern.assignNames(nameCounters)
                self.ret.assignNames(nameCounters)
                for assigned in assignment.values():
                    assigned.assignNames(nameCounters)

                # resolve types from assignments
                nameLookup = {}
                types = odict()
                for x in self.parameters:
                    types[x.name] = self.resolve(x.pattern, assignment, nameLookup)
                output = self.resolve(self.ret, assignment, nameLookup)

                signature = tuple([(k, self.makeHashable(v)) for k, v in types.items()] + [(None, self.makeHashable(output))])
                if signature not in considered:
                    pfas.append(self.renderAsPFA(fcnName, valueOverrides, nameLookup, types, output, nondeterministic))
                    considered.add(signature)

        return pfas

    @staticmethod
    def generateSafeValue(t, fcnName, valueOverrides, nameLookup):
        if isinstance(t, basestring) and t.startswith("Record"):
            t = nameLookup[t]

        if t == "null":
            return None
        elif t == "boolean":
            return True
        elif t == "int":
            return 5
        elif t == "long":
            return 5
        elif t == "float":
            return 0.5
        elif t == "double":
            return 0.5
        elif t == "string":
            return "hello"
        elif t == "bytes":
            return base64.b64encode("hello")

        elif isinstance(t, (dict, odict)) and t["type"] == "array":
            return [Signature.generateSafeValue(t["items"], fcnName, valueOverrides, nameLookup)] * 3

        elif isinstance(t, (dict, odict)) and t["type"] == "map":
            return odict(zip(["one", "two", "three"], [Signature.generateSafeValue(t["values"], fcnName, valueOverrides, nameLookup)] * 3))

        elif isinstance(t, (dict, odict)) and t["type"] == "record":
            out = odict()
            for f in t["fields"]:
                done = False
                if fcnName in valueOverrides and f["name"] in valueOverrides[fcnName]:
                    for vo in valueOverrides[fcnName][f["name"]]:
                        if vo["type"] is None or vo["type"] == f["type"]:
                            out[f["name"]] = vo["values"][0]
                            done = True
                if not done:
                    out[f["name"]] = Signature.generateSafeValue(f["type"], fcnName, valueOverrides, nameLookup)
                    
            return out

        elif isinstance(t, (dict, odict)) and t["type"] == "enum":
            return t["symbols"][0]

        elif isinstance(t, (dict, odict)) and t["type"] == "fixed":
            return base64.b64encode("\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55")

        elif isinstance(t, (list, tuple)):
            tpe = t[0]
            if isinstance(tpe, (dict, odict)) and tpe["type"] in ("record", "enum", "fixed"):
                name = tpe["name"]
            elif isinstance(tpe, (dict, odict)):
                name = tpe["type"]
            elif isinstance(tpe, basestring):
                name = tpe
            else:
                raise Exception

            if name == "null":
                return None
            else:
                return {name: Signature.generateSafeValue(tpe, fcnName, valueOverrides, nameLookup)}

        else:
            raise Exception

    @staticmethod
    def generateValue(t, fcnName, valueOverrides, nameLookup):
        if isinstance(t, basestring) and t.startswith("Record"):
            t = nameLookup[t]

        if t == "null":
            return [None]
        elif t == "boolean":
            return [False, True]
        elif t == "int":
            return [0, 1, -1, 2, -2, 17, -17, 5, -5, -100, 100]
        elif t == "long":
            return [0, 1, -1, 2, -2, 17, -17, 5, -5, -100, 100]
        elif t == "float":
            return [0.0, 0.00001, 0.99999, 1.0, 1.00001, -0.00001, -0.99999, -1.0, -1.00001, 17.0, -17.0, 100.0, -100.0, 0.1, 0.5, 0.9, -0.1, -0.5, -0.9, "inf", "-inf", "nan"]
        elif t == "double":
            return [0.0, 0.00001, 0.99999, 1.0, 1.00001, -0.00001, -0.99999, -1.0, -1.00001, 17.0, -17.0, 100.0, -100.0, 0.1, 0.5, 0.9, -0.1, -0.5, -0.9, "inf", "-inf", "nan"]
        elif t == "string":
            return [u"", u"o", u"hello", u"oneee\u2212two"]
        elif t == "bytes":
            return [base64.b64encode(""), base64.b64encode("o"), base64.b64encode("hello"), base64.b64encode("\x00"), base64.b64encode("\xff\x80\x00")]

        elif isinstance(t, (dict, odict)) and t["type"] == "array":
            sub = Signature.generateValue(t["items"], fcnName, valueOverrides, nameLookup)
            if len(sub) >= 4:
                return [[], sub[0:1], sub[1:3], [sub[3]] + list(sub[3:]) + [sub[-1]]]
            else:
                return [[], sub]

        elif isinstance(t, (dict, odict)) and t["type"] == "map":
            sub = Signature.generateValue(t["values"], fcnName, valueOverrides, nameLookup)
            if len(sub) >= 4:
                return [odict(), odict([("one", sub[0])]), odict([("one", sub[1]), ("two", sub[2])]), odict([(str(i), x) for i, x in enumerate(sub[3:])])]
            else:
                return [odict(), odict([(str(i), x) for i, x in enumerate(sub)])]

        elif isinstance(t, (dict, odict)) and t["type"] == "record":
            subtypes = odict((f["name"], f["type"]) for f in t["fields"])
            return Signature.generateValues(fcnName, valueOverrides, subtypes, nameLookup, None)

        elif isinstance(t, (dict, odict)) and t["type"] == "enum":
            return t["symbols"]

        elif isinstance(t, (dict, odict)) and t["type"] == "fixed" and t["size"] == 16:
            return [base64.b64encode("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
                    base64.b64encode("\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55"),
                    base64.b64encode("\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00"),
                    base64.b64encode("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")]
                    
        elif isinstance(t, (list, tuple)):
            out = []
            for tpe in t:
                if isinstance(tpe, (dict, odict)) and tpe["type"] in ("record", "enum", "fixed"):
                    name = tpe["name"]
                elif isinstance(tpe, (dict, odict)):
                    name = tpe["type"]
                elif isinstance(tpe, basestring):
                    name = tpe
                else:
                    raise Exception

                if name == "null":
                    out.append(None)
                else:
                    out.extend([{name: x} for x in Signature.generateValue(tpe, fcnName, valueOverrides, nameLookup)])

            return out
            
        else:
            print t
            raise Exception

    @staticmethod
    def generateValues(fcnName, valueOverrides, types, nameLookup, errs):
        if len(types) == 0:
            return []

        thispar, thistype = types.items()[0]

        done = False
        if fcnName in valueOverrides and thispar in valueOverrides[fcnName]:
            for vo in valueOverrides[fcnName][thispar]:
                if vo["type"] is None or vo["type"] == thistype:
                    these = vo["values"]
                    done = True
        if not done:
            these = Signature.generateValue(thistype, fcnName, valueOverrides, nameLookup)

        others = Signature.generateValues(fcnName, valueOverrides, odict(types.items()[1:]), nameLookup, errs)

        if len(these) * len(others) > 10000:
            targetLenHalf = int(math.ceil(10000 / float(len(these) * 2)))
            others = others[:targetLenHalf] + others[-targetLenHalf:]

        if len(others) == 0:
            out = []
            for thischoice in these:
                item = odict()
                item[thispar] = thischoice
                out.append(item)
            return out
        else:
            out = []
            for thischoice in these:
                for other in others:
                    item = odict()
                    item[thispar] = thischoice
                    for thatpar, thatchoice in other.items():
                        item[thatpar] = thatchoice
                    out.append(item)
            return out

    unknownCounter = 0
    @staticmethod
    def generateTrials(fcnName, valueOverrides, types, nameLookup, nondeterministic, errs=None, hint=None):
        out = []

        # generate samples that are specifically crafted to produce error conditions
        if errs is not None:
            base = odict()
            for n, t in types.items():
                done = False
                if fcnName in valueOverrides and n in valueOverrides[fcnName]:
                    for vo in valueOverrides[fcnName][n]:
                        if vo["type"] is None or vo["type"] == t:
                            base[n] = vo["values"][0]
                            done = True
                if not done:
                    base[n] = Signature.generateSafeValue(t, fcnName, valueOverrides, nameLookup)

            signature = json.loads(json.dumps(types))  # to drop odicts and break any references
            signature[None] = json.loads(json.dumps(output))

            for code, conditions in errs.items():
                for condition in conditions:
                    if odict((k, v) for k, v in condition["type"].items() if not (isinstance(v, (dict, odict)) and "params" in v)) == signature:
                        sample = odict(base, **condition["value"])
                        # we already know what the result of this sample should be: an error
                        out.append("          " + json.dumps(odict([("sample", sample), ("error", code)])))

        # generate samples whose result is not known yet
        samples = Signature.generateValues(fcnName, valueOverrides, types, nameLookup, errs)
        if "zipmap" in fcnName and len(samples) > 50:
            resamples = []
            for sample in samples:
                if len(set(map(len, sample.values()))) == 1:
                    resamples.append(sample)
            samples = resamples
        if fcnName == "a.combinations" or fcnName == "a.permutations":
            resamples = []
            for sample in samples:
                if len(sample["a"]) <= 3:
                    resamples.append(sample)
            samples = resamples

        for sample in samples:
            if nondeterministic is not None:
                # nondeterministic functions should be executed, their results type-checked, but not compared against any fixed value
                out.append("          " + json.dumps(odict([("sample", sample), ("result", "UNKNOWN_%07d" % Signature.unknownCounter), ("nondeterministic", nondeterministic)])))
                Signature.unknownCounter += 1
            else:
                # deterministic functions have a specific result, but we don't know it yet; we'll have to look at some implementations to see what it should be
                out.append("          " + json.dumps(odict([("sample", sample), ("result", "UNKNOWN_%07d" % Signature.unknownCounter)])))
                Signature.unknownCounter += 1

        # if the function signature has no arguments, generate one empty input
        if len(out) == 0 and len(types) == 0:
            if nondeterministic is not None:
                out.append("          " + json.dumps(odict([("sample", {}), ("result", "UNKNOWN_%07d" % Signature.unknownCounter), ("nondeterministic", nondeterministic)])))
                Signature.unknownCounter += 1
            else:
                out.append("          " + json.dumps(odict([("sample", {}), ("result", "UNKNOWN_%07d" % Signature.unknownCounter)])))
                Signature.unknownCounter += 1

        return out

    @staticmethod
    def formatPFA(types, output, fcnName, arguments, trials):
        pfaDocument = '''{"input":
               {"type": "record",
                "name": "Input",
                "fields": [
%s
                ]},
           "output":
               %s,
           "action":
               {"%s": [
%s
               ]}
          }''' % (",\n".join('''                    {"name": "%s", "type": %s}''' % (n, json.dumps(t)) for n, t in types.items() if not isinstance(t, Function)),
                  json.dumps(output),
                  fcnName,
                  ",\n".join("                   " + x for x in arguments))

        return '''     {"function": "%s",
      "engine":
          %s,
      "trials": [
%s
      ]
     }''' % (fcnName,
             pfaDocument,
             ",\n".join(trials))

    @staticmethod
    def renderAsPFA(fcnName, valueOverrides, nameLookup, types, output, nondeterministic, errs=None, hint=None):
        arguments = []
        for n, t in types.items():
            if isinstance(t, Function):
                params = [{"p{0}".format(i + 1): x} for i, x in enumerate(t.parameters)]
                ret = t.ret
                do = Signature.createFunction(params, ret, nameLookup)
                fcn = odict([("params", params), ("ret", ret), ("do", do)])
                arguments.append(json.dumps(fcn))
            else:
                arguments.append(json.dumps("input." + n))

        trials = Signature.generateTrials(fcnName,
                                          valueOverrides,
                                          odict([(k, v) for k, v in types.items() if not isinstance(v, Function)]),
                                          nameLookup,
                                          nondeterministic,
                                          errs, hint=hint)

        return Signature.formatPFA(types, output, fcnName, arguments, trials)
    
    @staticmethod
    def findNames(x, nameLookup):
        if isinstance(x, (dict, odict)) and x["type"] == "record":
            nameLookup[x["name"]] = x
            for f in x["fields"]:
                Signature.findNames(f["type"], nameLookup)
        elif isinstance(x, (dict, odict)) and x["type"] == "enum":
            nameLookup[x["name"]] = x
        elif isinstance(x, (dict, odict)) and x["type"] == "fixed":
            nameLookup[x["name"]] = x
        elif isinstance(x, (dict, odict)) and x["type"] == "array":
            Signature.findNames(x["items"], nameLookup)
        elif isinstance(x, (dict, odict)) and x["type"] == "map":
            Signature.findNames(x["values"], nameLookup)
        elif isinstance(x, (list, tuple)):
            for t in x:
                Signature.findNames(t, nameLookup)

    @staticmethod
    def makeHashable(x):
        if isinstance(x, (dict, odict)):
            return tuple([(k, Signature.makeHashable(x[k])) for k in sorted(x)])
        elif isinstance(x, (list, tuple)):
            return tuple(Signature.makeHashable(xi) for xi in x)
        elif isinstance(x, (basestring, int, long, float)) or x in (None, True, False):
            return x
        elif isinstance(x, Function):
            return ("fcn", Signature.makeHashable(x.parameters), Signature.makeHashable(x.ret))
        else:
            raise Exception("%s %s" % (repr(x), repr(type(x))))

    @staticmethod
    def createNumber(n, t, nameLookup):
        if isinstance(t, basestring) and t.startswith("Record"):
            t = nameLookup[t]
        if t in ("int", "double"):
            return n
        elif isinstance(t, (dict, odict)) and t["type"] == "array":
            return {"a.len": n}
        elif t == "string":
            return {"s.len": n}
        elif isinstance(t, (dict, odict)) and t["type"] == "record" and len(t["fields"]) == 0:
            return 0
        elif isinstance(t, (dict, odict)) and t["type"] == "record" and t["fields"][0]["type"] == "int":
            return {"attr": n, "path": [{"string": t["fields"][0]["name"]}]}
        elif isinstance(t, (dict, odict)) and t["type"] == "record" and sorted(x["name"] for x in t["fields"]) == ["fail", "pass"]:
            return 0
        elif isinstance(t, (dict, odict)) and t["type"] == "record" and sorted(x["name"] for x in t["fields"]) == ["fail", "missing", "pass"]:
            return 0
        elif t == ["null", "double"]:
            return {"ifnotnull": {"dummy": n}, "then": "dummy", "else": 3.14}
        else:
            print n, t
            raise Exception

    @staticmethod
    def createFunction(params, ret, nameLookup):
        if len(params) == 1 and ret == "string":
            p1 = Signature.createNumber(params[0].keys()[0], params[0].values()[0], nameLookup)
            return {"s.int": {"cast.long": p1}}

        elif len(params) == 1 and ret in ("int", "double"):
            p1 = Signature.createNumber(params[0].keys()[0], params[0].values()[0], nameLookup)
            if ret == "int":
                return {"cast.int": p1}
            else:
                return p1

        elif len(params) == 2 and ret in ("int", "double"):
            p1 = Signature.createNumber(params[0].keys()[0], params[0].values()[0], nameLookup)
            p2 = Signature.createNumber(params[1].keys()[0], params[1].values()[0], nameLookup)
            if ret == "int":
                return {"cast.int": {"+": [p1, p2]}}
            else:
                return {"+": [p1, p2]}

        elif len(params) == 3 and ret in ("int", "double"):
            p1 = Signature.createNumber(params[0].keys()[0], params[0].values()[0], nameLookup)
            p2 = Signature.createNumber(params[1].keys()[0], params[1].values()[0], nameLookup)
            p3 = Signature.createNumber(params[2].keys()[0], params[2].values()[0], nameLookup)
            if ret == "int":
                return {"cast.int": {"+": [{"+": [p1, p2]}, p3]}}
            else:
                return {"+": [{"+": [p1, p2]}, p3]}

        elif len(params) == 4 and ret in ("int", "double"):
            p1 = Signature.createNumber(params[0].keys()[0], params[0].values()[0], nameLookup)
            p2 = Signature.createNumber(params[1].keys()[0], params[1].values()[0], nameLookup)
            p3 = Signature.createNumber(params[2].keys()[0], params[2].values()[0], nameLookup)
            p4 = Signature.createNumber(params[3].keys()[0], params[3].values()[0], nameLookup)
            if ret == "int":
                return {"cast.int": {"+": [{"+": [{"+": [p1, p2]}, p3]}, p4]}}
            else:
                return {"+": [{"+": [{"+": [p1, p2]}, p3]}, p4]}

        elif len(params) == 5 and ret in ("int", "double"):
            p1 = Signature.createNumber(params[0].keys()[0], params[0].values()[0], nameLookup)
            p2 = Signature.createNumber(params[1].keys()[0], params[1].values()[0], nameLookup)
            p3 = Signature.createNumber(params[2].keys()[0], params[2].values()[0], nameLookup)
            p4 = Signature.createNumber(params[3].keys()[0], params[3].values()[0], nameLookup)
            p5 = Signature.createNumber(params[4].keys()[0], params[4].values()[0], nameLookup)
            if ret == "int":
                return {"cast.int": {"+": [{"+": [{"+": [{"+": [p1, p2]}, p3]}, p4]}, p5]}}
            else:
                return {"+": [{"+": [{"+": [{"+": [p1, p2]}, p3]}, p4]}, p5]}

        elif len(params) == 1 and ret == "boolean":
            p1 = Signature.createNumber(params[0].keys()[0], params[0].values()[0], nameLookup)
            return {"<": [p1, 2]}

        elif len(params) == 2 and ret == "boolean":
            p1 = Signature.createNumber(params[0].keys()[0], params[0].values()[0], nameLookup)
            p2 = Signature.createNumber(params[1].keys()[0], params[1].values()[0], nameLookup)
            return {"<": [p1, p2]}

        elif len(params) == 3 and ret == "boolean":
            p1 = Signature.createNumber(params[0].keys()[0], params[0].values()[0], nameLookup)
            p2 = Signature.createNumber(params[1].keys()[0], params[1].values()[0], nameLookup)
            p3 = Signature.createNumber(params[2].keys()[0], params[2].values()[0], nameLookup)
            return {"&&": [{"<": [p1, p2]}, {"<": [p2, p3]}]}

        elif len(params) == 2 and isinstance(ret, (list, tuple)) and sorted(ret) == ["boolean", "null"]:
            p1 = Signature.createNumber(params[0].keys()[0], params[0].values()[0], nameLookup)
            p2 = Signature.createNumber(params[1].keys()[0], params[1].values()[0], nameLookup)
            return {"upcast": {"<": [p1, p2]}, "as": ret}

        elif len(params) == 1 and sorted(ret) == ["double", "null"]:
            p1 = Signature.createNumber(params[0].keys()[0], params[0].values()[0], nameLookup)
            return {"upcast": {"cast.double": p1}, "as": ["null", "double"]}

        elif len(params) == 2 and sorted(ret) == ["double", "null"]:
            p1 = Signature.createNumber(params[0].keys()[0], params[0].values()[0], nameLookup)
            p2 = Signature.createNumber(params[1].keys()[0], params[1].values()[0], nameLookup)
            return {"upcast": {"cast.int": {"+": [p1, p2]}}, "as": ["null", "double"]}

        elif len(params) == 3 and sorted(ret) == ["double", "null"]:
            p1 = Signature.createNumber(params[0].keys()[0], params[0].values()[0], nameLookup)
            p2 = Signature.createNumber(params[1].keys()[0], params[1].values()[0], nameLookup)
            p3 = Signature.createNumber(params[2].keys()[0], params[2].values()[0], nameLookup)
            return {"upcast": {"cast.int": {"+": [{"+": [p1, p2]}, p3]}}, "as": ["null", "double"]}

        elif len(params) == 4 and sorted(ret) == ["double", "null"]:
            p1 = Signature.createNumber(params[0].keys()[0], params[0].values()[0], nameLookup)
            p2 = Signature.createNumber(params[1].keys()[0], params[1].values()[0], nameLookup)
            p3 = Signature.createNumber(params[2].keys()[0], params[2].values()[0], nameLookup)
            p4 = Signature.createNumber(params[3].keys()[0], params[3].values()[0], nameLookup)
            return {"upcast": {"cast.int": {"+": [{"+": [{"+": [p1, p2]}, p3]}, p4]}}, "as": ["null", "double"]}

        elif len(params) == 5 and sorted(ret) == ["double", "null"]:
            p1 = Signature.createNumber(params[0].keys()[0], params[0].values()[0], nameLookup)
            p2 = Signature.createNumber(params[1].keys()[0], params[1].values()[0], nameLookup)
            p3 = Signature.createNumber(params[2].keys()[0], params[2].values()[0], nameLookup)
            p4 = Signature.createNumber(params[3].keys()[0], params[3].values()[0], nameLookup)
            p5 = Signature.createNumber(params[4].keys()[0], params[4].values()[0], nameLookup)
            return {"upcast": {"cast.int": {"+": [{"+": [{"+": [{"+": [p1, p2]}, p3]}, p4]}, p5]}}, "as": ["null", "double"]}

        elif len(params) == 1 and isinstance(ret, (dict, odict)) and ret["type"] == "array" and sorted(ret["items"]) == ["double", "null"]:
            p1 = Signature.createNumber(params[0].keys()[0], params[0].values()[0], nameLookup)
            return {"type": ret, "new": [{"upcast": {"cast.double": p1}, "as": ["null", "double"]}, None]}

        elif len(params) == 2 and isinstance(ret, (dict, odict)) and ret["type"] == "array" and sorted(ret["items"]) == ["double", "null"]:
            p1 = Signature.createNumber(params[0].keys()[0], params[0].values()[0], nameLookup)
            p2 = Signature.createNumber(params[1].keys()[0], params[1].values()[0], nameLookup)
            return {"type": ret, "new": [{"upcast": {"cast.int": {"+": [p1, p2]}}, "as": ["null", "double"]}, None]}

        elif len(params) == 1 and isinstance(ret, (dict, odict)) and ret["type"] == "map" and sorted(ret["values"]) == ["double", "null"]:
            p1 = Signature.createNumber(params[0].keys()[0], params[0].values()[0], nameLookup)
            return [{"let": {"q1": {"upcast": {"cast.double": p1}, "as": ["null", "double"]}, "out": {"type": ret, "value": {}}}}, {"set": {"out": {"map.add": ["out", {"s.concat": [{"s.int": {"cast.int": {"*": [p1, 1000000]}}}, {"string": "..."}]}, "q1"]}}}, {"set": {"out": {"map.add": ["out", {"s.concat": [{"s.int": {"cast.int": {"*": [p1, 1000000]}}}, {"string": "...?"}]}, None]}}}, "out"]

        elif len(params) == 2 and isinstance(ret, (dict, odict)) and ret["type"] == "map" and sorted(ret["values"]) == ["double", "null"]:
            p1 = Signature.createNumber(params[0].keys()[0], params[0].values()[0], nameLookup)
            p2 = Signature.createNumber(params[1].keys()[0], params[1].values()[0], nameLookup)
            return [{"let": {"q1": {"upcast": {"cast.double": p1}, "as": ["null", "double"]}, "q2": {"upcast": {"cast.double": p2}, "as": ["null", "double"]}, "out": {"type": ret, "value": {}}}}, {"set": {"out": {"map.add": ["out", {"s.concat": [{"s.int": {"cast.int": {"*": [p1, 1000000]}}}, {"string": "..."}]}, "q1"]}}}, {"set": {"out": {"map.add": ["out", {"s.concat": [{"s.int": {"cast.int": {"*": [p2, 1000000]}}}, {"string": "..."}]}, "q2"]}}}, {"set": {"out": {"map.add": ["out", {"s.concat": [{"s.int": {"cast.int": {"*": [p2, 1000000]}}}, {"string": "...?"}]}, None]}}}, "out"]

        elif len(params) == 1 and sorted(ret) == ["int", "null"]:
            p1 = Signature.createNumber(params[0].keys()[0], params[0].values()[0], nameLookup)
            return {"upcast": {"cast.int": p1}, "as": ["null", "int"]}

        elif len(params) == 2 and sorted(ret) == ["int", "null"]:
            p1 = Signature.createNumber(params[0].keys()[0], params[0].values()[0], nameLookup)
            p2 = Signature.createNumber(params[1].keys()[0], params[1].values()[0], nameLookup)
            return {"upcast": {"cast.int": {"+": [p1, p2]}}, "as": ["null", "int"]}

        elif len(params) == 1 and ret == {"type": "array", "items": "int"}:
            p1 = Signature.createNumber(params[0].keys()[0], params[0].values()[0], nameLookup)
            return {"type": {"type": "array", "items": "int"}, "new": [{"cast.int": p1}, {"cast.int": p1}, {"cast.int": p1}]}

        elif len(params) == 2 and ret == {"type": "array", "items": "int"}:
            p1 = Signature.createNumber(params[0].keys()[0], params[0].values()[0], nameLookup)
            p2 = Signature.createNumber(params[1].keys()[0], params[1].values()[0], nameLookup)
            return {"type": {"type": "array", "items": "int"}, "new": [{"cast.int": p1}, {"cast.int": p2}]}

        elif len(params) == 1 and ret == {"type": "map", "values": "int"}:
            p1 = Signature.createNumber(params[0].keys()[0], params[0].values()[0], nameLookup)
            return [{"let": {"q1": {"cast.int": p1}, "out": {"type": {"type": "map", "values": "int"}, "value": {}}}}, {"set": {"out": {"map.add": ["out", {"s.concat": [{"s.int": "q1"}, {"string": "..."}]}, "q1"]}}}, "out"]

        elif len(params) == 2 and ret == {"type": "map", "values": "int"}:
            p1 = Signature.createNumber(params[0].keys()[0], params[0].values()[0], nameLookup)
            p2 = Signature.createNumber(params[1].keys()[0], params[1].values()[0], nameLookup)
            return [{"let": {"q1": {"cast.int": p1}, "q2": {"cast.int": p2}, "out": {"type": {"type": "map", "values": "int"}, "value": {}}}}, {"set": {"out": {"map.add": ["out", {"s.concat": [{"s.int": "q1"}, {"string": "..."}]}, "q1"]}}}, {"set": {"out": {"map.add": ["out", {"s.concat": [{"s.int": "q2"}, {"string": "..."}]}, "q2"]}}}, "out"]

        elif ret == {"type": "array", "items": "string"}:
            return {"type": ret, "value": ["one", "two", "three"]}

        elif ret == {"type": "array", "items": {"type": "array", "items": "string"}}:
            return {"type": ret, "value": [["one", "two"], ["three"]]}

        elif ret == {"type": "map", "values": {"type": "array", "items": "string"}}:
            return {"type": ret, "value": {"uno": ["one", "two"], "dos": ["three"]}}

        elif sorted(ret) == [{"type": "array", "items": "string"}, "null"]:
            return {"type": [{"type": "array", "items": "string"}, "null"], "value": {"array": ["one", "two", "three"]}}

        elif len(params) == 1 and isinstance(ret, (dict, odict)) and ret["type"] == "record" and ret["fields"] == [{"name": "x", "type": "int"}, {"name": "y", "type": "string"}]:
            p1 = Signature.createNumber(params[0].keys()[0], params[0].values()[0], nameLookup)
            return {"type": ret["name"], "new": {"x": {"cast.int": p1}, "y": {"s.int": {"cast.int": p1}}}}

        elif len(params) == 2 and isinstance(ret, (dict, odict)) and ret["type"] == "record" and ret["fields"] == [{"name": "x", "type": "int"}, {"name": "y", "type": "string"}]:
            p1 = Signature.createNumber(params[0].keys()[0], params[0].values()[0], nameLookup)
            p2 = Signature.createNumber(params[1].keys()[0], params[1].values()[0], nameLookup)
            return {"type": ret["name"], "new": {"x": {"cast.int": {"+": [p1, p2]}}, "y": {"s.int": {"cast.int": {"+": [p1, p2]}}}}}

        elif len(params) == 3 and isinstance(ret, (dict, odict)) and ret["type"] == "record" and ret["fields"] == [{"name": "x", "type": "int"}, {"name": "y", "type": "string"}]:
            p1 = Signature.createNumber(params[0].keys()[0], params[0].values()[0], nameLookup)
            p2 = Signature.createNumber(params[1].keys()[0], params[1].values()[0], nameLookup)
            p3 = Signature.createNumber(params[2].keys()[0], params[2].values()[0], nameLookup)
            return {"type": ret["name"], "new": {"x": {"cast.int": {"+": [{"+": [p1, p2]}, p3]}}, "y": {"s.int": {"cast.int": {"+": [{"+": [p1, p2]}, p3]}}}}}

        elif len(params) == 4 and isinstance(ret, (dict, odict)) and ret["type"] == "record" and ret["fields"] == [{"name": "x", "type": "int"}, {"name": "y", "type": "string"}]:
            p1 = Signature.createNumber(params[0].keys()[0], params[0].values()[0], nameLookup)
            p2 = Signature.createNumber(params[1].keys()[0], params[1].values()[0], nameLookup)
            p3 = Signature.createNumber(params[2].keys()[0], params[2].values()[0], nameLookup)
            p4 = Signature.createNumber(params[3].keys()[0], params[3].values()[0], nameLookup)
            return {"type": ret["name"], "new": {"x": {"cast.int": {"+": [{"+": [{"+": [p1, p2]}, p3]}, p4]}}, "y": {"s.int": {"cast.int": {"+": [{"+": [{"+": [p1, p2]}, p3]}, p4]}}}}}

        elif len(params) == 5 and isinstance(ret, (dict, odict)) and ret["type"] == "record" and ret["fields"] == [{"name": "x", "type": "int"}, {"name": "y", "type": "string"}]:
            p1 = Signature.createNumber(params[0].keys()[0], params[0].values()[0], nameLookup)
            p2 = Signature.createNumber(params[1].keys()[0], params[1].values()[0], nameLookup)
            p3 = Signature.createNumber(params[2].keys()[0], params[2].values()[0], nameLookup)
            p4 = Signature.createNumber(params[3].keys()[0], params[3].values()[0], nameLookup)
            p5 = Signature.createNumber(params[4].keys()[0], params[4].values()[0], nameLookup)
            return {"type": ret["name"], "new": {"x": {"cast.int": {"+": [{"+": [{"+": [{"+": [p1, p2]}, p3]}, p4]}, p5]}}, "y": {"s.int": {"cast.int": {"+": [{"+": [{"+": [{"+": [p1, p2]}, p3]}, p4]}, p5]}}}}}

        elif len(params) == 1 and isinstance(ret, (dict, odict)) and ret["type"] == "array" and isinstance(ret["items"], (dict, odict)) and ret["items"]["type"] == "record" and ret["items"]["fields"] == [{"name": "x", "type": "int"}, {"name": "y", "type": "string"}]:
            p1 = Signature.createNumber(params[0].keys()[0], params[0].values()[0], nameLookup)
            return {"type": {"type": "array", "items": ret["items"]["name"]}, "new": [{"type": ret["items"]["name"], "new": {"x": {"cast.int": p1}, "y": {"s.int": {"cast.int": p1}}}}]}

        elif len(params) == 2 and isinstance(ret, (dict, odict)) and ret["type"] == "array" and isinstance(ret["items"], (dict, odict)) and ret["items"]["type"] == "record" and ret["items"]["fields"] == [{"name": "x", "type": "int"}, {"name": "y", "type": "string"}]:
            p1 = Signature.createNumber(params[0].keys()[0], params[0].values()[0], nameLookup)
            p2 = Signature.createNumber(params[1].keys()[0], params[1].values()[0], nameLookup)
            return {"type": {"type": "array", "items": ret["items"]["name"]}, "new": [{"type": ret["items"]["name"], "new": {"x": {"cast.int": {"+": [p1, p2]}}, "y": {"s.int": {"cast.int": {"+": [p1, p2]}}}}}]}

        elif len(params) == 1 and isinstance(ret, (dict, odict)) and ret["type"] == "map" and isinstance(ret["values"], (dict, odict)) and ret["values"]["type"] == "record" and ret["values"]["fields"] == [{"name": "x", "type": "int"}, {"name": "y", "type": "string"}]:
            p1 = Signature.createNumber(params[0].keys()[0], params[0].values()[0], nameLookup)
            return [{"let": {"q1": {"cast.int": p1}, "out2": {"type": {"type": "map", "values": ret["values"]["name"]}, "value": {}}}}, {"set": {"out2": {"map.add": ["out2", {"s.concat": [{"s.int": "q1"}, {"string": "..."}]}, {"type": ret["values"]["name"], "new": {"x": "q1", "y": {"s.int": "q1"}}}]}}}, "out2"]

        elif len(params) == 2 and isinstance(ret, (dict, odict)) and ret["type"] == "map" and isinstance(ret["values"], (dict, odict)) and ret["values"]["type"] == "record" and ret["values"]["fields"] == [{"name": "x", "type": "int"}, {"name": "y", "type": "string"}]:
            p1 = Signature.createNumber(params[0].keys()[0], params[0].values()[0], nameLookup)
            p2 = Signature.createNumber(params[1].keys()[0], params[1].values()[0], nameLookup)
            return [{"let": {"q1": {"cast.int": p1}, "q2": {"cast.int": p2}, "out2": {"type": {"type": "map", "values": ret["values"]["name"]}, "value": {}}}}, {"set": {"out2": {"map.add": ["out2", {"s.concat": [{"s.int": "q1"}, {"string": "..."}]}, {"type": ret["values"]["name"], "new": {"x": "q1", "y": {"s.int": "q1"}}}]}}}, {"set": {"out2": {"map.add": ["out2", {"s.concat": [{"s.int": "q2"}, {"string": "..."}]}, {"type": ret["values"]["name"], "new": {"x": "q2", "y": {"s.int": "q2"}}}]}}}, "out2"]

        elif len(params) == 1 and isinstance(ret, (list, tuple)) and ret[1] == "null" and isinstance(ret[0], (dict, odict)) and ret[0]["type"] == "record" and ret[0]["fields"] == [{"name": "x", "type": "int"}, {"name": "y", "type": "string"}]:
            p1 = Signature.createNumber(params[0].keys()[0], params[0].values()[0], nameLookup)
            return {"upcast": {"type": ret[0]["name"], "new": {"x": {"cast.int": p1}, "y": {"s.int": {"cast.int": p1}}}}, "as": [ret[0]["name"], "null"]}

        elif len(params) == 2 and isinstance(ret, (list, tuple)) and ret[1] == "null" and isinstance(ret[0], (dict, odict)) and ret[0]["type"] == "record" and ret[0]["fields"] == [{"name": "x", "type": "int"}, {"name": "y", "type": "string"}]:
            p1 = Signature.createNumber(params[0].keys()[0], params[0].values()[0], nameLookup)
            p2 = Signature.createNumber(params[1].keys()[0], params[1].values()[0], nameLookup)
            return {"upcast": {"type": ret[0]["name"], "new": {"x": {"cast.int": {"+": [p1, p2]}}, "y": {"s.int": {"cast.int": {"+": [p1, p2]}}}}}, "as": [ret[0]["name"], "null"]}

        elif params == [{"p1": "Record1"}, {"p2": "Record1"}] and ret == "Record1" and nameLookup["Record1"]["fields"] == [{"name": "x", "type": "int"}, {"name": "y", "type": "string"}]:
            return {"type": "Record1", "new": {"x": {"+": ["p1.x", "p2.x"]}, "y": {"s.concat": ["p1.y", "p2.y"]}}}

        elif params == [{"p1": "Record2"}, {"p2": "Record1"}] and ret == "Record2" and nameLookup["Record1"]["fields"] == [{"name": "x", "type": "int"}, {"name": "y", "type": "string"}] and nameLookup["Record2"]["fields"] == [{"name": "x", "type": "int"}, {"name": "y", "type": "string"}]:
            return {"type": "Record2", "new": {"x": {"+": ["p1.x", "p2.x"]}, "y": {"s.concat": ["p1.y", "p2.y"]}}}

        elif params == [{"p1": "Record1"}, {"p2": {"type": "array", "items": "string"}}] and ret == "Record1" and nameLookup["Record1"]["fields"] == [{"name": "x", "type": "int"}, {"name": "y", "type": "string"}]:
            return {"type": "Record1", "new": {"x": "p1.x", "y": {"s.concat": ["p1.y", {"attr": "p2", "path": [0]}]}}}

        elif len(params) == 2 and params[0]["p1"] == "Record1" and ret == "Record1" and nameLookup["Record1"]["fields"] == [{"name": "x", "type": "int"}, {"name": "y", "type": "string"}]:
            p2 = Signature.createNumber(params[1].keys()[0], params[1].values()[0], nameLookup)
            return {"type": "Record1", "new": {"x": {"+": ["p1.x", {"cast.int": p2}]}, "y": "p1.y"}}

        elif len(params) == 2 and params[0]["p1"] == "Record1" and params[1]["p2"] == "Record2" and nameLookup["Record1"]["fields"] == [{"name": "x", "type": "int"}, {"name": "y", "type": "string"}] and nameLookup["Record2"]["fields"] == [{"name": "x", "type": "int"}, {"name": "y", "type": "string"}] and sorted(ret) == ["boolean", "null"]:
            return {"<": ["p1.x", "p2.x"]}

        elif len(params) == 2 and params[0]["p1"] == "int" and isinstance(params[1]["p2"], (dict, odict)) and params[1]["p2"]["type"] == "array" and isinstance(ret, (dict, odict)) and ret["type"] == "record" and ret["fields"][0]["name"] == "center":
            if ret["fields"][0]["type"] == {"type": "array", "items": "int"}:
                return {"type": ret["name"], "value": {"center": [1, 2, 3]}}
            elif ret["fields"][0]["type"] == {"type": "array", "items": {"type": "array", "items": "string"}}:
                return {"type": ret["name"], "value": {"center": [["one", "two"], ["three"]]}}
            elif ret["fields"][0]["type"] == {"type": "array", "items": {"type": "record", "name": "Record2", "fields": [{"name": "x", "type": "int"}, {"name": "y", "type": "string"}]}}:
                return {"type": ret["name"], "value": {"center": [{"x": 1, "y": "one"}, {"x": 2, "y": "two"}, {"x": 3, "y": "three"}]}}
            elif ret["fields"][0]["type"] == {"type": "array", "items": {"type": "record", "name": "Record3", "fields": [{"name": "x", "type": "int"}, {"name": "y", "type": "string"}]}}:
                return {"type": ret["name"], "value": {"center": [{"x": 1, "y": "one"}, {"x": 2, "y": "two"}, {"x": 3, "y": "three"}]}}
            elif ret["fields"][0]["type"] == {"type": "array", "items": ["null", "double"]}:
                return {"type": ret["name"], "value": {"center": [{"double": 3.14}, None]}}
            elif ret["fields"][0]["type"] == {"type": "array", "items": "double"}:
                return {"type": ret["name"], "value": {"center": [3.14, 3.14, 3.14]}}
            else:
                print "params", params
                print "ret", ret
                raise Exception

        elif len(params) == 2 and isinstance(params[1]["p2"], basestring) and params[1]["p2"].startswith("Record") and params[1]["p2"] == ret:
            return "p2"

        else:
            raise Exception

    @staticmethod
    def resolve(pattern, assignment, nameLookup):
        if isinstance(pattern, Primitive):
            return pattern.name

        elif isinstance(pattern, (Any, Record, Enum, Fixed)) and pattern.label is not None:
            return Signature.resolve(assignment[pattern.label], assignment, nameLookup)

        elif isinstance(pattern, Ref):
            if isinstance(assignment[pattern.label], (Record, Enum, Fixed)):
                return assignment[pattern.label].name
            else:
                return Signature.resolve(assignment[pattern.label], assignment, nameLookup)

        elif isinstance(pattern, Array):
            return odict([("type", "array"), ("items", Signature.resolve(pattern.items, assignment, nameLookup))])

        elif isinstance(pattern, Map):
            return odict([("type", "map"), ("values", Signature.resolve(pattern.values, assignment, nameLookup))])

        elif isinstance(pattern, Record):
            if pattern.name in nameLookup:
                return pattern.name
            else:
                out = odict([("type", "record"), ("name", pattern.name), ("fields", [odict([("name", x.name), ("type", Signature.resolve(x.type, assignment, nameLookup))]) for x in pattern.fields])])
                nameLookup[out["name"]] = out
                return out

        elif isinstance(pattern, Enum):
            if pattern.name in nameLookup:
                return pattern.name
            elif pattern.ofRecord is not None:
                out = odict([("type", "enum"), ("name", pattern.name), ("symbols", [x.name for x in assignment[pattern.ofRecord].fields])])
                nameLookup[out["name"]] = out
                return out
            else:
                out = odict([("type", "enum"), ("name", pattern.name), ("symbols", pattern.symbols)])
                nameLookup[out["name"]] = out
                return out

        elif isinstance(pattern, Fixed):
            if pattern.name in nameLookup:
                return pattern.name
            else:
                out = odict([("type", "fixed"), ("name", pattern.name), ("size", pattern.size)])
                nameLookup[out["name"]] = out
                return out

        elif isinstance(pattern, Union):
            resolved = [Signature.resolve(x, assignment, nameLookup) for x in pattern.types]
            out = []
            for x in resolved:
                if isinstance(x, (list, tuple)):
                    for xi in x:
                        if xi not in out:
                            out.append(xi)
                else:
                    if x not in out:
                        out.append(x)
            return out

        elif isinstance(pattern, Function):
            parameters = [Signature.resolve(x, assignment, nameLookup) for x in pattern.parameters]
            ret = Signature.resolve(pattern.ret, assignment, nameLookup)
            return Function(parameters, ret)

        else:
            raise Exception

    @staticmethod
    def assignments(labels):
        if len(labels) == 0:
            return []
        else:
            thislabel, constraints = labels.items()[0]

            if len(constraints) == 0:
                choices = [Primitive("int"), Array(Primitive("string")), Record(None, [Field("x", Primitive("int")), Field("y", Primitive("string"))]), Union([Primitive("null"), Primitive("double")])]

            elif all(isinstance(x, Primitive) for x in constraints):
                choices = constraints

            elif len(constraints) == 2 and constraints[0] == "record" and len(constraints[1]) == 0:
                choices = [Record(None, [Field("x", Primitive("int")), Field("y", Primitive("string"))])]

            elif len(constraints) == 2 and constraints[0] == "record" and len(constraints[1]) > 0:
                choices = [Record(None, constraints[1])]

            elif constraints == ["enum"]:
                choices = [Enum(None, None, symbols=["one", "two", "three"])]

            elif len(constraints) == 2 and constraints[0] == "enum":
                choices = [Enum(None, constraints[1])]

            elif constraints == ["fixed"]:
                choices = [Fixed(None, size=16)]

            else:
                raise Exception

            others = Signature.assignments(odict(labels.items()[1:]))

            if len(others) == 0:
                out = []
                for thischoice in choices:
                    item = odict()
                    item[thislabel] = thischoice
                    out.append(item)
                return out

            else:
                out = []
                for thischoice in choices:
                    for other in others:
                        item = odict()
                        item[thislabel] = thischoice
                        for thatlabel, thatchoice in other.items():
                            item[thatlabel] = thatchoice
                        out.append(item)
                return out

class Parameter(object):
    def __init__(self, par):
        self.name = par.attrib["name"]
        self.pattern = pattern(par)
    def __repr__(self):
        return "Parameter(" + repr(self.name) + ", " + repr(self.pattern) + ")"
    def getlabels(self, labels):
        self.pattern.getlabels(labels)

class Pattern(object):
    def getlabels(self, labels):
        pass
    def assignNames(self, nameCounters):
        pass

class Primitive(Pattern):
    def __init__(self, name):
        self.name = name
    def __repr__(self):
        return "Primitive(" + repr(self.name) + ")"

class Any(Pattern):
    def __init__(self, label, of):
        self.label = label
        if of is None:
            self.of = []
        else:
            self.of = [Primitive(x) for x in of.split(", ")]
    def __repr__(self):
        return "Label(" + repr(self.label) + ", [" + ", ".join(repr(x) for x in self.of) + "])"
    def getlabels(self, labels):
        if self.label in labels:
            raise Exception
        else:
            labels[self.label] = self.of

class Ref(Pattern):
    def __init__(self, label):
        self.label = label
    def __repr__(self):
        return "Ref(" + repr(self.label) + ")"
    def getlabels(self, labels):
        if self.label not in labels:
            raise Exception

class Array(Pattern):
    def __init__(self, items):
        self.items = items
    def __repr__(self):
        return "Array(" + repr(self.items) + ")"
    def getlabels(self, labels):
        self.items.getlabels(labels)
    def assignNames(self, nameCounters):
        self.items.assignNames(nameCounters)

class Map(Pattern):
    def __init__(self, values):
        self.values = values
    def __repr__(self):
        return "Map(" + repr(self.values) + ")"
    def getlabels(self, labels):
        self.values.getlabels(labels)
    def assignNames(self, nameCounters):
        self.values.assignNames(nameCounters)

class Record(Pattern):
    def __init__(self, label, fields, name=None):
        self.label = label
        self.fields = fields
        self.name = name
    def __repr__(self):
        return "Record(" + repr(self.label) + ", [" + ", ".join(repr(x) for x in self.fields) + "])"
    def getlabels(self, labels):
        if self.label in labels:
            raise Exception
        else:
            labels[self.label] = ["record", self.fields]
            for x in self.fields:
                x.getlabels(labels)
    def assignNames(self, nameCounters):
        if self.label is None:
            self.name = "Record" + str(nameCounters["record"])
            nameCounters["record"] += 1
        for x in self.fields:
            x.type.assignNames(nameCounters)

class Field(Pattern):
    def __init__(self, name, type):
        self.name = name
        self.type = type
    def __repr__(self):
        return "Field(" + repr(self.name) + ", " + repr(self.type) + ")"
    def getlabels(self, labels):
        self.type.getlabels(labels)

class Enum(Pattern):
    def __init__(self, label, ofRecord, name=None, symbols=None):
        self.label = label
        self.ofRecord = ofRecord
        self.name = name
        self.symbols = symbols
    def __repr__(self):
        return "Enum(" + repr(self.label) + ", " + repr(self.ofRecord) + ")"
    def getlabels(self, labels):
        if self.label in labels:
            raise Exception
        else:
            if self.ofRecord is None:
                labels[self.label] = ["enum"]
            else:
                labels[self.label] = ["enum", self.ofRecord]
    def assignNames(self, nameCounters):
        if self.label is None:
            self.name = "Enum" + str(nameCounters["enum"])
            nameCounters["enum"] += 1

class Fixed(Pattern):
    def __init__(self, label, name=None, size=None):
        self.label = label
        self.name = name
        self.size = size
    def __repr__(self):
        return "Fixed(" + repr(self.label) + ")"
    def getlabels(self, labels):
        if self.label in labels:
            raise Exception
        else:
            labels[self.label] = ["fixed"]
    def assignNames(self, nameCounters):
        if self.label is None:
            self.name = "Fixed" + str(nameCounters["fixed"])
            nameCounters["fixed"] += 1

class Union(Pattern):
    def __init__(self, types):
        self.types = types
    def __repr__(self):
        return "Union([" + ", ".join(repr(x) for x in self.types) + "])"
    def getlabels(self, labels):
        for x in self.types:
            x.getlabels(labels)
    def assignNames(self, nameCounters):
        for x in self.types:
            x.assignNames(nameCounters)

class Function(Pattern):
    def __init__(self, parameters, ret):
        self.parameters = parameters
        self.ret = ret
    def __repr__(self):
        return "Function([" + ", ".join(repr(x) for x in self.parameters) + "], " + repr(self.ret) + ")"
    def getlabels(self, labels):
        for x in self.parameters:
            x.getlabels(labels)
        self.ret.getlabels(labels)
    def assignNames(self, nameCounters):
        for x in self.parameters:
            x.assignNames(nameCounters)
        self.ret.assignNames(nameCounters)

def pattern(par):
    children = par.getchildren()

    if len(children) == 0:
        return Primitive(par.text)

    elif len(children) == 1 and children[0].tag == "any":
        return Any(children[0].attrib["label"], children[0].attrib.get("of", None))

    elif len(children) == 1 and children[0].tag == "ref":
        return Ref(children[0].attrib["label"])

    elif len(children) == 1 and children[0].tag == "array":
        return Array(pattern(children[0]))

    elif len(children) == 1 and children[0].tag == "map":
        return Map(pattern(children[0]))

    elif len(children) == 1 and children[0].tag == "record":
        return Record(children[0].attrib["label"],
                      [Field(x.attrib["name"], pattern(x)) for x in children[0].findall("./field")])

    elif len(children) == 1 and children[0].tag == "enum":
        return Enum(children[0].attrib["label"], children[0].attrib.get("ofRecord", None))

    elif len(children) == 1 and children[0].tag == "fixed":
        return Fixed(children[0].attrib["label"])

    elif all(x.tag == "union" for x in children):
        return Union([pattern(x) for x in children])

    elif len(children) == 1 and children[0].tag == "function":
        return Function([pattern(x) for x in children[0].findall("./par")], pattern(children[0].find("./ret")))

    else:
        raise Exception

# def patternToType(x):
#     if isinstance(x, Primitive):
#         return x.name
#     elif isinstance(x, Array):
#         items = patternToType(x.items)
#         if isinstance(items, Pattern):
#             return x
#         else:
#             return odict([("type", "array"), ("items", items)])
#     elif isinstance(x, Map):
#         values = patternToType(x.values)
#         if isinstance(values, Pattern):
#             return x
#         else:
#             return odict([("type", "map"), ("values", values)])
#     elif isinstance(x, Record):
#         fields = [odict([("name", f.name), ("type", patternToType(f.type))]) for f in x.fields]
#         if any(isinstance(f["type"], Pattern) for f in fields):
#             return x
#         else:
#             return odict([("type", "record"), ("name", "Record"), ("fields", fields)])
#     elif isinstance(x, Union):
#         types = [patternToType(t) for t in x.types]
#         if any(isinstance(t, Pattern) for t in types):
#             return x
#         else:
#             return types
#     else:
#         return x

# def represent(x):
#     t = patternToType(x)
#     if isinstance(t, Pattern):
#         return repr(t)
#     else:
#         return t

# for fcn in libfcns.findall("libfcns/fcn"):
#     if any(okaySig(sig) for sig in fcn.findall("./sig")):
#         for error in fcn.findall("./doc/error"):
#             code = int(error.attrib["code"])
#             cases = []
#             for sig in fcn.findall("./sig"):
#                 pat = Signature(sig)
#                 cases.append(odict([("value", "HERE"), ("type", odict([(x.name, represent(x.pattern)) for x in pat.parameters if not isinstance(x.pattern, Function)] + [("", represent(pat.ret))]))]))
#             print "    #", fcn.attrib["name"] + ":", re.sub("</error>", "", re.sub("<error code=\"[0-9]+\">", "", xml.etree.ElementTree.tostring(error))).replace("&lt;", "<").replace("&gt;", ">").strip()
#             print "    %d:" % code, json.dumps(cases).replace('"":', 'None:').replace('"HERE"', 'HERE') + ","

### NOTE: domain is not used (they're all True)

errorConditions = {
    # //: If <p>y</p> is zero, this function raises a "division by zero" runtime error.
    18040: [{"value": {"x": 3, "y": 0}, "domain": lambda x, y: True, "type": {"x": "int", "y": "int", None: "int"}}, {"value": {"x": 3, "y": 0}, "domain": lambda x, y: True, "type": {"x": "long", "y": "long", None: "long"}}],
    # %: If <p>n</p> is zero and <p>k</p> and <p>n</p> are int or long, this function raises a "division by zero" runtime error.
    18060: [{"value": {"k": 3, "n": 0}, "domain": lambda k, n: True, "type": {"k": "int", "n": "int", None: "int"}}, {"value": {"k": 3, "n": 0}, "domain": lambda k, n: True, "type": {"k": "long", "n": "long", None: "long"}}],
    # %: If <p>n</p> is zero and <p>k</p> and <p>n</p> are int or long, this function raises a "division by zero" runtime error.
    18070: [{"value": {"k": 3, "n": 0}, "domain": lambda k, n: True, "type": {"k": "int", "n": "int", None: "int"}}, {"value": {"k": 3, "n": 0}, "domain": lambda k, n: True, "type": {"k": "long", "n": "long", None: "long"}}],
    # m.link.softmax: If <p>x</p> is an empty array or an empty map, this function raises an "empty input" error.
    25000: [{"value": {"x": []}, "domain": lambda x, y: True, "type": {"x": {"type": "array", "items": "double"}, None: {"type": "array", "items": "double"}}}, {"value": {"x": {}}, "domain": lambda x, y: True, "type": {"x": {"type": "map", "values": "double"}, None: {"type": "map", "values": "double"}}}],
    # la.dot: If <p>x</p> or <p>y</p> has fewer than 1 row or fewer than 1 column, this function raises a "too few rows/cols" error.
    24051: [{"value": {"x": [[], []]}, "domain": lambda x, y: True, "type": {"x": {"type": "array", "items": {"type": "array", "items": "double"}}, "y": {"type": "array", "items": "double"}, None: {"type": "array", "items": "double"}}}, {"value": {"x": []}, "domain": lambda x, y: True, "type": {"x": {"type": "array", "items": {"type": "array", "items": "double"}}, "y": {"type": "array", "items": "double"}, None: {"type": "array", "items": "double"}}}, {"value": {"y": []}, "domain": lambda x, y: True, "type": {"x": {"type": "array", "items": {"type": "array", "items": "double"}}, "y": {"type": "array", "items": "double"}, None: {"type": "array", "items": "double"}}}, {"value": {"x": {"one": {}, "two": {}}, "y": {}}, "domain": lambda x, y: True, "type": {"x": {"type": "map", "values": {"type": "map", "values": "double"}}, "y": {"type": "map", "values": "double"}, None: {"type": "map", "values": "double"}}}, {"value": {"x": {}, "y": {}}, "domain": lambda x, y: True, "type": {"x": {"type": "map", "values": {"type": "map", "values": "double"}}, "y": {"type": "map", "values": "double"}, None: {"type": "map", "values": "double"}}}, {"value": {"x": [[], []]}, "domain": lambda x, y: True, "type": {"x": {"type": "array", "items": {"type": "array", "items": "double"}}, "y": {"type": "array", "items": {"type": "array", "items": "double"}}, None: {"type": "array", "items": {"type": "array", "items": "double"}}}}, {"value": {"x": []}, "domain": lambda x, y: True, "type": {"x": {"type": "array", "items": {"type": "array", "items": "double"}}, "y": {"type": "array", "items": {"type": "array", "items": "double"}}, None: {"type": "array", "items": {"type": "array", "items": "double"}}}}, {"value": {"y": [[], []]}, "domain": lambda x, y: True, "type": {"x": {"type": "array", "items": {"type": "array", "items": "double"}}, "y": {"type": "array", "items": {"type": "array", "items": "double"}}, None: {"type": "array", "items": {"type": "array", "items": "double"}}}}, {"value": {"y": []}, "domain": lambda x, y: True, "type": {"x": {"type": "array", "items": {"type": "array", "items": "double"}}, "y": {"type": "array", "items": {"type": "array", "items": "double"}}, None: {"type": "array", "items": {"type": "array", "items": "double"}}}}, {"value": {"x": {"one": {}, "two": {}}, "y": {"one": {}, "two": {}}}, "domain": lambda x, y: True, "type": {"x": {"type": "map", "values": {"type": "map", "values": "double"}}, "y": {"type": "map", "values": {"type": "map", "values": "double"}}, None: {"type": "map", "values": {"type": "map", "values": "double"}}}}, {"value": {"x": {}, "y": {}}, "domain": lambda x, y: True, "type": {"x": {"type": "map", "values": {"type": "map", "values": "double"}}, "y": {"type": "map", "values": {"type": "map", "values": "double"}}, None: {"type": "map", "values": {"type": "map", "values": "double"}}}}],
    # la.eigenBasis: If <p>x</p> contains non-finite values, this function raises a "non-finite matrix" error.</error>
    24113: [{"value": {"x": [[1, 2, 3], [1, 4, "inf"], [9, 9, 3]]}, "domain": lambda x: True, "type": {"x": {"type": "array", "items": {"type": "array", "items": "double"}}, None: {"type": "array", "items": {"type": "array", "items": "double"}}}}, {"value": {"x": [[1, 2, 3], [1, 4, "-inf"], [9, 9, 3]]}, "domain": lambda x: True, "type": {"x": {"type": "array", "items": {"type": "array", "items": "double"}}, None: {"type": "array", "items": {"type": "array", "items": "double"}}}}, {"value": {"x": [[1, 2, 3], [1, 4, "nan"], [9, 9, 3]]}, "domain": lambda x: True, "type": {"x": {"type": "array", "items": {"type": "array", "items": "double"}}, None: {"type": "array", "items": {"type": "array", "items": "double"}}}}, {"value": {"x": {"one": {"one": 1, "two": 2, "three": 3}, "two": {"one": 1, "two": 4, "three": "inf"}, "three": {"one": 9, "two": 9, "three": 3}}}, "domain": lambda x: True, "type": {"x": {"type": "map", "values": {"type": "map", "values": "double"}}, None: {"type": "map", "values": {"type": "map", "values": "double"}}}}, {"value": {"x": {"one": {"one": 1, "two": 2, "three": 3}, "two": {"one": 1, "two": 4, "three": "-inf"}, "three": {"one": 9, "two": 9, "three": 3}}}, "domain": lambda x: True, "type": {"x": {"type": "map", "values": {"type": "map", "values": "double"}}, None: {"type": "map", "values": {"type": "map", "values": "double"}}}}, {"value": {"x": {"one": {"one": 1, "two": 2, "three": 3}, "two": {"one": 1, "two": 4, "three": "nan"}, "three": {"one": 9, "two": 9, "three": 3}}}, "domain": lambda x: True, "type": {"x": {"type": "map", "values": {"type": "map", "values": "double"}}, None: {"type": "map", "values": {"type": "map", "values": "double"}}}}],
    # rand.string: Raises an "population must be non-empty" error if <p>population</p> is empty.
    34083: [{"value": {"size": 1, "population": ""}, "domain": lambda size, population: True, "type": {"size": "int", "population": "string", None: "string"}}],
    # rand.bytes: Raises an "population must be non-empty" error if <p>population</p> is empty.
    34093: [{"value": {"size": 1, "population": ""}, "domain": lambda size, population: True, "type": {"size": "int", "population": "bytes", None: "bytes"}}],
    15670: [{"value": {"a": []}, "domain": lambda a: True, "type": {"a": {"type": "array", "items": "int"}, "fcn": {"params": ["int", "int"], "ret": "int"}, None: "int"}}],
    15680: [{"value": {"a": []}, "domain": lambda a: True, "type": {"a": {"type": "array", "items": "int"}, "fcn": {"params": ["int", "int"], "ret": "int"}, None: "int"}}],
    # +: Integer results above or below -2147483648 and 2147483647 (inclusive) produce an "int overflow" runtime error.
    18000: [{"value": {"x": 2147483640, "y": 10}, "domain": lambda x, y: True, "type": {"x": "int", "y": "int", None: "int"}}],
    # +: Long-integer results above or below -9223372036854775808 and 9223372036854775807 (inclusive) produce a "long overflow" runtime error.
    18001: [{"value": {"x": 9223372036854775800, "y": 10}, "domain": lambda x, y: True, "type": {"x": "long", "y": "long", None: "long"}}],
    # -: Integer results above or below -2147483648 and 2147483647 (inclusive) produce an "int overflow" runtime error.
    18010: [{"value": {"x": -2147483648, "y": 10}, "domain": lambda x, y: True, "type": {"x": "int", "y": "int", None: "int"}}],
    # -: Long-integer results above or below -9223372036854775808 and 9223372036854775807 (inclusive) produce a "long overflow" runtime error.
    18011: [{"value": {"x": -9223372036854775800, "y": 10}, "domain": lambda x, y: True, "type": {"x": "long", "y": "long", None: "long"}}],
    # *: Integer results above or below -2147483648 and 2147483647 (inclusive) produce an "int overflow" runtime error.
    18020: [{"value": {"x": 1073741824, "y": 2}, "domain": lambda x, y: True, "type": {"x": "int", "y": "int", None: "int"}}],
    # *: Long-integer results above or below -9223372036854775808 and 9223372036854775807 (inclusive) produce a "long overflow" runtime error.
    18021: [{"value": {"x": 4611686018427387904, "y": 2}, "domain": lambda x, y: True, "type": {"x": "long", "y": "long", None: "long"}}],
    # u-: For exactly one integer value, -2147483648, this function produces an "int overflow" runtime error.
    18050: [{"value": {"x": -2147483648}, "domain": lambda x: True, "type": {"x": "int", None: "int"}}],
    # u-: For exactly one long value, -9223372036854775808, this function produces a "long overflow" runtime error.
    18051: [{"value": {"x": -9223372036854775808}, "domain": lambda x: True, "type": {"x": "long", None: "long"}}],
    # **: Integer results above or below -2147483648 and 2147483647 (inclusive) produce an "int overflow" runtime error.
    18080: [{"value": {"x": 46341, "y": 2}, "domain": lambda x, y: True, "type": {"x": "int", "y": "int", None: "int"}}],
    # **: Long-integer results above or below -9223372036854775808 and 9223372036854775807 (inclusive) produce a "long overflow" runtime error.
    18081: [{"value": {"x": 3037000500, "y": 2}, "domain": lambda x, y: True, "type": {"x": "long", "y": "long", None: "long"}}],
    # m.abs: For exactly one integer value, -2147483648, this function produces an "int overflow" runtime error.
    27020: [{"value": {"x": -2147483648}, "domain": lambda x: True, "type": {"x": "int", None: "int"}}],
    # m.abs: For exactly one long value, -9223372036854775808, this function produces a "long overflow" runtime error.
    27021: [{"value": {"x": -9223372036854775808}, "domain": lambda x: True, "type": {"x": "long", None: "long"}}],
    # m.log: If <p>base</p> is less than or equal to zero, this function produces a "base must be positive" runtime error.
    27170: [{"value": {"base": 0}, "domain": lambda x, base: True, "type": {"x": "double", "base": "int", None: "double"}}],
    # m.round: Integer results outside of -2147483648 and 2147483647 (inclusive) produce an "int overflow" runtime error.
    27190: [{"value": {"x": 2247483650.0}, "domain": lambda x: True, "type": {"x": "float", None: "int"}}],
    # m.round: Long-integer results outside of -9223372036854775808 and 9223372036854775807 (inclusive) produce a "long overflow" runtime error.
    27191: [{"value": {"x": 9323372036854775810.0}, "domain": lambda x: True, "type": {"x": "double", None: "long"}}],
    # m.special.nChooseK: Raises "domain error" if <m>k \leq 0</m> and <m>n \leq k</m>.
    36000: [{"value": {"n": 0}, "domain": lambda n, k: True, "type": {"n": "int", "k": "int", None: "int"}}],
    # m.special.lnBeta: Raises "domain error" if <m>a \leq 0</m> or if <m>b \leq 0</m>.
    36010: [{"value": {"a": 0}, "domain": lambda a, b: True, "type": {"a": "double", "b": "double", None: "double"}}, {"value": {"b": 0}, "domain": lambda a, b: True, "type": {"a": "double", "b": "double", None: "double"}}],
    # m.kernel.linear: Raises a "arrays must have same length" error if the lengths of <p>x</p> and <p>y</p> are not the same.
    23000: [{"value": {"x": [1, 2, 3], "y": [1, 2]}, "domain": lambda x, y: True, "type": {"x": {"type": "array", "items": "double"}, "y": {"type": "array", "items": "double"}, None: "double"}}],
    # m.kernel.rbf: Raises a "arrays must have same length" error if the lengths of <p>x</p> and <p>y</p> are not the same.
    23010: [{"value": {"x": [1, 2, 3], "y": [1, 2]}, "domain": lambda x, y, gamma: True, "type": {"x": {"type": "array", "items": "double"}, "y": {"type": "array", "items": "double"}, "gamma": "double", None: "double"}}],
    # m.kernel.poly: Raises a "arrays must have same length" error if the lengths of <p>x</p> and <p>y</p> are not the same.
    23020: [{"value": {"x": [1, 2, 3], "y": [1, 2]}, "domain": lambda x, y, gamma, intercept, degree: True, "type": {"x": {"type": "array", "items": "double"}, "y": {"type": "array", "items": "double"}, "gamma": "double", "intercept": "double", "degree": "double", None: "double"}}],
    # m.kernel.sigmoid: Raises a "arrays must have same length" error if the lengths of <p>x</p> and <p>y</p> are not the same.
    23030: [{"value": {"x": [1, 2, 3], "y": [1, 2]}, "domain": lambda x, y, gamma, intercept: True, "type": {"x": {"type": "array", "items": "double"}, "y": {"type": "array", "items": "double"}, "gamma": "double", "intercept": "double", None: "double"}}],
    # la.zipmap: In the array signature, if any element in <p>x</p> does not have a corresponding element in <p>y</p> (or vice-versa), this function raises a "misaligned matrices" error.
    24020: [{"value": {"x": [[1, 2, 3], [1, 2, 3], [1, 2, 3]], "y": [[1, 2, 3], [1, 2, 3], [1, 2]]}, "domain": lambda x, y, fcn: True, "type": {"x": {"type": "array", "items": {"type": "array", "items": "double"}}, "y": {"type": "array", "items": {"type": "array", "items": "double"}}, "fcn": {"params": ["double", "double"], "ret": "double"}, None: {"type": "array", "items": {"type": "array", "items": "double"}}}}, {"value": {"x": [[1, 2, 3], [1, 2, 3], [1, 2, 3]], "y": [[1, 2], [1, 2], [1, 2]]}, "domain": lambda x, y, fcn: True, "type": {"x": {"type": "array", "items": {"type": "array", "items": "double"}}, "y": {"type": "array", "items": {"type": "array", "items": "double"}}, "fcn": {"params": ["double", "double"], "ret": "double"}, None: {"type": "array", "items": {"type": "array", "items": "double"}}}}, {"value": {"x": [[1, 2, 3], [1, 2, 3], [1, 2, 3]], "y": [[1, 2, 3], [1, 2, 3]]}, "domain": lambda x, y, fcn: True, "type": {"x": {"type": "array", "items": {"type": "array", "items": "double"}}, "y": {"type": "array", "items": {"type": "array", "items": "double"}}, "fcn": {"params": ["double", "double"], "ret": "double"}, None: {"type": "array", "items": {"type": "array", "items": "double"}}}}],
    # la.add: In the array signature, if any element in <p>x</p> does not have a corresponding element in <p>y</p> (or vice-versa), this function raises a "misaligned matrices" error.
    24030: [{"value": {"x": [1, 2, 3], "y": [1, 2]}, "domain": lambda x, y: True, "type": {"x": {"type": "array", "items": "double"}, "y": {"type": "array", "items": "double"}, None: {"type": "array", "items": "double"}}}, {"value": {"x": [[1, 2, 3], [1, 2, 3]], "y": [[1, 2], [1, 2]]}, "domain": lambda x, y: True, "type": {"x": {"type": "array", "items": {"type": "array", "items": "double"}}, "y": {"type": "array", "items": {"type": "array", "items": "double"}}, None: {"type": "array", "items": {"type": "array", "items": "double"}}}}],
    # la.sub: In the array signature, if any element in <p>x</p> does not have a corresponding element in <p>y</p> (or vice-versa), this function raises a "misaligned matrices" error.
    24040: [{"value": {"x": [1, 2, 3], "y": [1, 2]}, "domain": lambda x, y: True, "type": {"x": {"type": "array", "items": "double"}, "y": {"type": "array", "items": "double"}, None: {"type": "array", "items": "double"}}}, {"value": {"x": [[1, 2, 3], [1, 2, 3]], "y": [[1, 2], [1, 2]]}, "domain": lambda x, y: True, "type": {"x": {"type": "array", "items": {"type": "array", "items": "double"}}, "y": {"type": "array", "items": {"type": "array", "items": "double"}}, None: {"type": "array", "items": {"type": "array", "items": "double"}}}}],
    # la.dot: In the array signature, if the dimensions of <p>x</p> do not correspond to the dimension(s) of <p>y</p>, this function raises a "misaligned matrices" error.
    24050: [{"value": {"x": [[1, 2, 3], [1, 2, 3]], "y": [1, 2]}, "domain": lambda x, y: True, "type": {"x": {"type": "array", "items": {"type": "array", "items": "double"}}, "y": {"type": "array", "items": "double"}, None: {"type": "array", "items": "double"}}}, {"value": {"x": [[1, 2, 3], [1, 2, 3]], "y": [[1, 2], [1, 2]]}, "domain": lambda x, y: True, "type": {"x": {"type": "array", "items": {"type": "array", "items": "double"}}, "y": {"type": "array", "items": {"type": "array", "items": "double"}}, None: {"type": "array", "items": {"type": "array", "items": "double"}}}}],
    # la.transpose: If the matrix has fewer than 1 row or fewer than 1 column, this function raises a "too few rows/cols" error.
    24060: [{"value": {"x": [[], []]}, "domain": lambda x: True, "type": {"x": {"type": "array", "items": {"type": "array", "items": "double"}}, None: {"type": "array", "items": {"type": "array", "items": "double"}}}}, {"value": {"x": []}, "domain": lambda x: True, "type": {"x": {"type": "array", "items": {"type": "array", "items": "double"}}, None: {"type": "array", "items": {"type": "array", "items": "double"}}}}, {"value": {"x": {"one": {}, "two": {}}}, "domain": lambda x: True, "type": {"x": {"type": "map", "values": {"type": "map", "values": "double"}}, None: {"type": "map", "values": {"type": "map", "values": "double"}}}}, {"value": {"x": {}}, "domain": lambda x: True, "type": {"x": {"type": "map", "values": {"type": "map", "values": "double"}}, None: {"type": "map", "values": {"type": "map", "values": "double"}}}}],
    # la.transpose: If the columns are ragged (arrays of different lengths or maps with different sets of keys), this function raises a "ragged columns" error.
    24061: [{"value": {"x": [[1, 2, 3], [1, 2]]}, "domain": lambda x: True, "type": {"x": {"type": "array", "items": {"type": "array", "items": "double"}}, None: {"type": "array", "items": {"type": "array", "items": "double"}}}}, {"value": {"x": {"one": {"uno": 1, "dos": 2, "tres": 3}, "two": {"uno": 1, "dos": 2}}}, "domain": lambda x: True, "type": {"x": {"type": "map", "values": {"type": "map", "values": "double"}}, None: {"type": "map", "values": {"type": "map", "values": "double"}}}}],
    # la.inverse: If the matrix has fewer than 1 row or fewer than 1 column, this function raises a "too few rows/cols" error.
    24070: [{"value": {"x": [[], []]}, "domain": lambda x: True, "type": {"x": {"type": "array", "items": {"type": "array", "items": "double"}}, None: {"type": "array", "items": {"type": "array", "items": "double"}}}}, {"value": {"x": []}, "domain": lambda x: True, "type": {"x": {"type": "array", "items": {"type": "array", "items": "double"}}, None: {"type": "array", "items": {"type": "array", "items": "double"}}}}, {"value": {"x": {"uno": {}, "dos": {}}}, "domain": lambda x: True, "type": {"x": {"type": "map", "values": {"type": "map", "values": "double"}}, None: {"type": "map", "values": {"type": "map", "values": "double"}}}}, {"value": {"x": {}}, "domain": lambda x: True, "type": {"x": {"type": "map", "values": {"type": "map", "values": "double"}}, None: {"type": "map", "values": {"type": "map", "values": "double"}}}}],
    # la.inverse: If <p>x</p> is an array with ragged columns (arrays of different lengths), this function raises a "ragged columns" error.
    24071: [{"value": {"x": [[1, 2, 3], [1, 2]]}, "domain": lambda x: True, "type": {"x": {"type": "array", "items": {"type": "array", "items": "double"}}, None: {"type": "array", "items": {"type": "array", "items": "double"}}}}],
    # la.trace: If <p>x</p> is an array with ragged columns (arrays of different lengths), this function raises a "ragged columns" error.
    24080: [{"value": {"x": [[1, 2, 3], [1, 2]]}, "domain": lambda x: True, "type": {"x": {"type": "array", "items": {"type": "array", "items": "double"}}, None: "double"}}],
    # la.det: If the matrix has fewer than 1 row or fewer than 1 column, this function raises a "too few rows/cols" error.
    24090: [{"value": {"x": [[], []]}, "domain": lambda x: True, "type": {"x": {"type": "array", "items": {"type": "array", "items": "double"}}, None: "double"}}, {"value": {"x": []}, "domain": lambda x: True, "type": {"x": {"type": "array", "items": {"type": "array", "items": "double"}}, None: "double"}}, {"value": {"x": {"one": {}, "two": {}}}, "domain": lambda x: True, "type": {"x": {"type": "map", "values": {"type": "map", "values": "double"}}, None: "double"}}, {"value": {"x": {}}, "domain": lambda x: True, "type": {"x": {"type": "map", "values": {"type": "map", "values": "double"}}, None: "double"}}],
    # la.det: If <p>x</p> is an array with ragged columns (arrays of different lengths), this function raises a "ragged columns" error.
    24091: [{"value": {"x": [[1, 2, 3], [1, 2]]}, "domain": lambda x: True, "type": {"x": {"type": "array", "items": {"type": "array", "items": "double"}}, None: "double"}}],
    # la.det: In the array signature, if <p>x</p> is not a square matrix, this function raises a "non-square matrix" error.
    24092: [{"value": {"x": [[1, 2, 3], [1, 4, 8]]}, "domain": lambda x: True, "type": {"x": {"type": "array", "items": {"type": "array", "items": "double"}}, None: "double"}}],
    # la.symmetric: If the matrix has fewer than 1 row or fewer than 1 column, this function raises a "too few rows/cols" error.
    24100: [{"value": {"x": [[], []]}, "domain": lambda x, tolerance: True, "type": {"x": {"type": "array", "items": {"type": "array", "items": "double"}}, "tolerance": "double", None: "boolean"}} , {"value": {"x": []}, "domain": lambda x, tolerance: True, "type": {"x": {"type": "array", "items": {"type": "array", "items": "double"}}, "tolerance": "double", None: "boolean"}} , {"value": {"x": {"one": {}, "two": {}}}, "domain": lambda x, tolerance: True, "type": {"x": {"type": "map", "values": {"type": "map", "values": "double"}}, "tolerance": "double", None: "boolean"}} , {"value": {"x": {}}, "domain": lambda x, tolerance: True, "type": {"x": {"type": "map", "values": {"type": "map", "values": "double"}}, "tolerance": "double", None: "boolean"}}],
    # la.symmetric: If <p>x</p> is an array with ragged columns (arrays of different lengths), this function raises a "ragged columns" error.
    24101: [{"value": {"x": [[1, 2, 3], [1, 2]]}, "domain": lambda x, tolerance: True, "type": {"x": {"type": "array", "items": {"type": "array", "items": "double"}}, "tolerance": "double", None: "boolean"}}],
    # la.symmetric: If <p>x</p> is not a square matrix, this function raises a "non-square matrix" error.
    24102: [{"value": {"x": [[1, 2, 3], [1, 4, 8]]}, "domain": lambda x, tolerance: True, "type": {"x": {"type": "array", "items": {"type": "array", "items": "double"}}, "tolerance": "double", None: "boolean"}}],
    # la.eigenBasis: If the matrix has fewer than 1 row or fewer than 1 column, this function raises a "too few rows/cols" error.
    24110: [{"value": {"x": [[], []]}, "domain": lambda x: True, "type": {"x": {"type": "array", "items": {"type": "array", "items": "double"}}, None: {"type": "array", "items": {"type": "array", "items": "double"}}}}, {"value": {"x": []}, "domain": lambda x: True, "type": {"x": {"type": "array", "items": {"type": "array", "items": "double"}}, None: {"type": "array", "items": {"type": "array", "items": "double"}}}}, {"value": {"x": {"one": {}, "two": {}}}, "domain": lambda x: True, "type": {"x": {"type": "map", "values": {"type": "map", "values": "double"}}, None: {"type": "map", "values": {"type": "map", "values": "double"}}}}, {"value": {"x": {}}, "domain": lambda x: True, "type": {"x": {"type": "map", "values": {"type": "map", "values": "double"}}, None: {"type": "map", "values": {"type": "map", "values": "double"}}}}],
    # la.eigenBasis: If <p>x</p> is an array with ragged columns (arrays of different lengths), this function raises a "ragged columns" error.
    24111: [{"value": {"x": [[1, 2, 3], [1, 2]]}, "domain": lambda x: True, "type": {"x": {"type": "array", "items": {"type": "array", "items": "double"}}, None: {"type": "array", "items": {"type": "array", "items": "double"}}}}],
    # la.eigenBasis: If <p>x</p> is not a square matrix, this function raises a "non-square matrix" error.
    24112: [{"value": {"x": [[1, 2, 3], [1, 4, 8]]}, "domain": lambda x: True, "type": {"x": {"type": "array", "items": {"type": "array", "items": "double"}}, None: {"type": "array", "items": {"type": "array", "items": "double"}}}}],
    # la.truncate: If the matrix has fewer than 1 row or fewer than 1 column, this function raises a "too few rows/cols" error.
    24120: [{"value": {"x": [[], []]}, "domain": lambda x, keep: True, "type": {"x": {"type": "array", "items": {"type": "array", "items": "double"}}, "keep": "int", None: {"type": "array", "items": {"type": "array", "items": "double"}}}}, {"value": {"x": []}, "domain": lambda x, keep: True, "type": {"x": {"type": "array", "items": {"type": "array", "items": "double"}}, "keep": "int", None: {"type": "array", "items": {"type": "array", "items": "double"}}}}, {"value": {"x": {"one": {}, "two": {}}}, "domain": lambda x, keep: True, "type": {"x": {"type": "map", "values": {"type": "map", "values": "double"}}, "keep": {"type": "array", "items": "string"}, None: {"type": "map", "values": {"type": "map", "values": "double"}}}}, {"value": {"x": {}}, "domain": lambda x, keep: True, "type": {"x": {"type": "map", "values": {"type": "map", "values": "double"}}, "keep": {"type": "array", "items": "string"}, None: {"type": "map", "values": {"type": "map", "values": "double"}}}}],
    # la.truncate: If <p>x</p> is an array with ragged columns (arrays of different lengths), this function raises a "ragged columns" error.
    24121: [{"value": {"x": [[1, 2, 3], [1, 2]]}, "domain": lambda x, keep: True, "type": {"x": {"type": "array", "items": {"type": "array", "items": "double"}}, "keep": "int", None: {"type": "array", "items": {"type": "array", "items": "double"}}}}],
    # metric.simpleEuclidean: Raises "dimensions of vectors do not match" if all vectors do not have the same dimension.
    28000: [{"value": {"x": [1, 2, 3], "y": [1, 2]}, "domain": lambda x, y: True, "type": {"x": {"type": "array", "items": "double"}, "y": {"type": "array", "items": "double"}, None: "double"}}],
    # metric.euclidean: Raises "dimensions of vectors do not match" if all vectors do not have the same dimension.
    28030: [{"value": {"x": [{"double": 1}, {"double": 2}, {"double": 3}], "y": [{"double": 1}, {"double": 2}]}, "domain": lambda similarity, x, y: True, "type": {"similarity": {"params": ["double", "double"], "ret": "double"}, "x": {"type": "array", "items": ["null", "double"]}, "y": {"type": "array", "items": ["null", "double"]}, None: "double"}}, {"value": {"x": [{"double": 1}, {"double": 2}, {"double": 3}], "y": [{"double": 1}, {"double": 2}]}, "domain": lambda similarity, x, y, missingWeight: True, "type": {"similarity": {"params": ["double", "double"], "ret": "double"}, "x": {"type": "array", "items": ["null", "double"]}, "y": {"type": "array", "items": ["null", "double"]}, "missingWeight": {"type": "array", "items": "double"}, None: "double"}}],
    # metric.squaredEuclidean: Raises "dimensions of vectors do not match" if all vectors do not have the same dimension.
    28040: [{"value": {"x": [{"double": 1}, {"double": 2}, {"double": 3}], "y": [{"double": 1}, {"double": 2}]}, "domain": lambda similarity, x, y: True, "type": {"similarity": {"params": ["double", "double"], "ret": "double"}, "x": {"type": "array", "items": ["null", "double"]}, "y": {"type": "array", "items": ["null", "double"]}, None: "double"}}, {"value": {"x": [{"double": 1}, {"double": 2}, {"double": 3}], "y": [{"double": 1}, {"double": 2}]}, "domain": lambda similarity, x, y, missingWeight: True, "type": {"similarity": {"params": ["double", "double"], "ret": "double"}, "x": {"type": "array", "items": ["null", "double"]}, "y": {"type": "array", "items": ["null", "double"]}, "missingWeight": {"type": "array", "items": "double"}, None: "double"}}],
    # metric.chebyshev: Raises "dimensions of vectors do not match" if all vectors do not have the same dimension.
    28050: [{"value": {"x": [{"double": 1}, {"double": 2}, {"double": 3}], "y": [{"double": 1}, {"double": 2}]}, "domain": lambda similarity, x, y: True, "type": {"similarity": {"params": ["double", "double"], "ret": "double"}, "x": {"type": "array", "items": ["null", "double"]}, "y": {"type": "array", "items": ["null", "double"]}, None: "double"}}, {"value": {"x": [{"double": 1}, {"double": 2}, {"double": 3}], "y": [{"double": 1}, {"double": 2}]}, "domain": lambda similarity, x, y, missingWeight: True, "type": {"similarity": {"params": ["double", "double"], "ret": "double"}, "x": {"type": "array", "items": ["null", "double"]}, "y": {"type": "array", "items": ["null", "double"]}, "missingWeight": {"type": "array", "items": "double"}, None: "double"}}],
    # metric.taxicab: Raises "dimensions of vectors do not match" if all vectors do not have the same dimension.
    28060: [{"value": {"x": [{"double": 1}, {"double": 2}, {"double": 3}], "y": [{"double": 1}, {"double": 2}]}, "domain": lambda similarity, x, y: True, "type": {"similarity": {"params": ["double", "double"], "ret": "double"}, "x": {"type": "array", "items": ["null", "double"]}, "y": {"type": "array", "items": ["null", "double"]}, None: "double"}}, {"value": {"x": [{"double": 1}, {"double": 2}, {"double": 3}], "y": [{"double": 1}, {"double": 2}]}, "domain": lambda similarity, x, y, missingWeight: True, "type": {"similarity": {"params": ["double", "double"], "ret": "double"}, "x": {"type": "array", "items": ["null", "double"]}, "y": {"type": "array", "items": ["null", "double"]}, "missingWeight": {"type": "array", "items": "double"}, None: "double"}}],
    # metric.minkowski: Raises "dimensions of vectors do not match" if all vectors do not have the same dimension.
    28070: [{"value": {"x": [{"double": 1}, {"double": 2}, {"double": 3}], "y": [{"double": 1}, {"double": 2}]}, "domain": lambda similarity, x, y, p: True, "type": {"similarity": {"params": ["double", "double"], "ret": "double"}, "x": {"type": "array", "items": ["null", "double"]}, "y": {"type": "array", "items": ["null", "double"]}, "p": "double", None: "double"}}, {"value": {"x": [{"double": 1}, {"double": 2}, {"double": 3}], "y": [{"double": 1}, {"double": 2}]}, "domain": lambda similarity, x, y, p, missingWeight: True, "type": {"similarity": {"params": ["double", "double"], "ret": "double"}, "x": {"type": "array", "items": ["null", "double"]}, "y": {"type": "array", "items": ["null", "double"]}, "p": "double", "missingWeight": {"type": "array", "items": "double"}, None: "double"}}],
    # metric.minkowski: Raises "Minkowski parameter p must be positive" if <p>p</p> is less than or equal to zero.
    28071: [{"value": {"x": [{"double": 1}, {"double": 2}, {"double": 3}], "y": [{"double": 1}, {"double": 2}, {"double": 3}], "missingWeight": [1, 1, 1], "p": -0.1}, "domain": lambda similarity, x, y, p, missingWeight: True, "type": {"similarity": {"params": ["double", "double"], "ret": "double"}, "x": {"type": "array", "items": ["null", "double"]}, "y": {"type": "array", "items": ["null", "double"]}, "p": "double", "missingWeight": {"type": "array", "items": "double"}, None: "double"}}, {"value": {"x": [{"double": 1}, {"double": 2}, {"double": 3}], "y": [{"double": 1}, {"double": 2}, {"double": 3}], "missingWeight": [1, 1, 1], "p": -10}, "domain": lambda similarity, x, y, p, missingWeight: True, "type": {"similarity": {"params": ["double", "double"], "ret": "double"}, "x": {"type": "array", "items": ["null", "double"]}, "y": {"type": "array", "items": ["null", "double"]}, "p": "double", "missingWeight": {"type": "array", "items": "double"}, None: "double"}}, {"value": {"x": [{"double": 1}, {"double": 2}, {"double": 3}], "y": [{"double": 1}, {"double": 2}, {"double": 3}], "missingWeight": [1, 1, 1], "p": "-inf"}, "domain": lambda similarity, x, y, p, missingWeight: True, "type": {"similarity": {"params": ["double", "double"], "ret": "double"}, "x": {"type": "array", "items": ["null", "double"]}, "y": {"type": "array", "items": ["null", "double"]}, "p": "double", "missingWeight": {"type": "array", "items": "double"}, None: "double"}}, {"value": {"x": [{"double": 1}, {"double": 2}, {"double": 3}], "y": [{"double": 1}, {"double": 2}, {"double": 3}], "missingWeight": [1, 1, 1], "p": "nan"}, "domain": lambda similarity, x, y, p, missingWeight: True, "type": {"similarity": {"params": ["double", "double"], "ret": "double"}, "x": {"type": "array", "items": ["null", "double"]}, "y": {"type": "array", "items": ["null", "double"]}, "p": "double", "missingWeight": {"type": "array", "items": "double"}, None: "double"}}],
    # metric.simpleMatching: Raises "dimensions of vectors do not match" if <p>x</p> and <p>y</p> do not have the same dimension.
    28080: [{"value": {"x": [True, False, True], "y": [True, False]}, "domain": lambda x, y: True, "type": {"x": {"type": "array", "items": "boolean"}, "y": {"type": "array", "items": "boolean"}, None: "double"}}],
    # metric.jaccard: Raises "dimensions of vectors do not match" if <p>x</p> and <p>y</p> do not have the same dimension.
    28090: [{"value": {"x": [True, False, True], "y": [True, False]}, "domain": lambda x, y: True, "type": {"x": {"type": "array", "items": "boolean"}, "y": {"type": "array", "items": "boolean"}, None: "double"}}],
    # metric.tanimoto: Raises "dimensions of vectors do not match" if <p>x</p> and <p>y</p> do not have the same dimension.
    28100: [{"value": {"x": [True, False, True], "y": [True, False]}, "domain": lambda x, y: True, "type": {"x": {"type": "array", "items": "boolean"}, "y": {"type": "array", "items": "boolean"}, None: "double"}}],
    # metric.binarySimilarity: Raises "dimensions of vectors do not match" if <p>x</p> and <p>y</p> do not have the same dimension.
    28110: [{"value": {"x": [True, False, True], "y": [True, False]}, "domain": lambda x, y, c00, c01, c10, c11, d00, d01, d10, d11: True, "type": {"x": {"type": "array", "items": "boolean"}, "y": {"type": "array", "items": "boolean"}, "c00": "double", "c01": "double", "c10": "double", "c11": "double", "d00": "double", "d01": "double", "d10": "double", "d11": "double", None: "double"}}],
    # rand.int: Raises a "high must be greater than low" error if <p>high</p> is less than or equal to <p>low</p>.
    34000: [{"value": {"low": 3, "high": 3}, "domain": lambda low, high: True, "type": {"low": "int", "high": "int", None: "int"}}, {"value": {"low": 3, "high": 2}, "domain": lambda low, high: True, "type": {"low": "int", "high": "int", None: "int"}}],
    # rand.long: Raises a "high must be greater than low" error if <p>high</p> is less than or equal to <p>low</p>.
    34010: [{"value": {"low": 3, "high": 3}, "domain": lambda low, high: True, "type": {"low": "long", "high": "long", None: "long"}}, {"value": {"low": 3, "high": 2}, "domain": lambda low, high: True, "type": {"low": "long", "high": "long", None: "long"}}],
    # rand.float: Raises a "high must be greater than low" error if <p>high</p> is less than or equal to <p>low</p>.
    34020: [{"value": {"low": 3.14, "high": 3.14}, "domain": lambda low, high: True, "type": {"low": "float", "high": "float", None: "float"}}, {"value": {"low": 3.14, "high": 2.2}, "domain": lambda low, high: True, "type": {"low": "float", "high": "float", None: "float"}}],
    # rand.double: Raises a "high must be greater than low" error if <p>high</p> is less than or equal to <p>low</p>.
    34030: [{"value": {"low": 3.14, "high": 3.14}, "domain": lambda low, high: True, "type": {"low": "double", "high": "double", None: "double"}}, {"value": {"low": 3.14, "high": 2.2}, "domain": lambda low, high: True, "type": {"low": "double", "high": "double", None: "double"}}],
    # rand.choice: Raises a "population must not be empty" error if <p>population</p> is empty.
    34040: [{"value": {"population": []}, "domain": lambda population: True, "type": {"population": {"type": "array", "items": "string"}, None: "string"}}],
    # rand.choices: Raises a "population must not be empty" error if <p>population</p> is empty.
    34050: [{"value": {"population": []}, "domain": lambda size, population: True, "type": {"size": "int", "population": {"type": "array", "items": "string"}, None: {"type": "array", "items": "string"}}}],
    # rand.sample: Raises a "population must not be empty" error if <p>population</p> is empty.
    34060: [{"value": {"population": []}, "domain": lambda size, population: True, "type": {"size": "int", "population": {"type": "array", "items": "string"}, None: {"type": "array", "items": "string"}}}],
    # rand.sample: Raises a "population smaller than requested subsample" error if the size of <p>population</p> is less than <p>size</p>.
    34061: [{"value": {"size": 4, "population": ["one", "two", "three"]}, "domain": lambda size, population: True, "type": {"size": "int", "population": {"type": "array", "items": "string"}, None: {"type": "array", "items": "string"}}}],
    # rand.histogram: Raises a "distribution must be non-empty" error if no items of <p>distribution</p> are non-zero.
    34070: [{"value": {"distribution": []}, "domain": lambda distribution: True, "type": {"distribution": {"type": "array", "items": "double"}, None: "int"}}, {"value": {"distribution": [0.0, 0.0, 0.0]}, "domain": lambda distribution: True, "type": {"distribution": {"type": "array", "items": "double"}, None: "int"}}, {"value": {"distribution": []}, "domain": lambda distribution: True, "type": {"distribution": {"type": "array", "items": {"type": "record", "name": "Record", "fields": [{"name": "prob", "type": "double"}]}}, None: "Record"}}, {"value": {"distribution": [{"prob": 0.0}, {"prob": 0.0}, {"prob": 0.0}]}, "domain": lambda distribution: True, "type": {"distribution": {"type": "array", "items": {"type": "record", "name": "Record", "fields": [{"name": "prob", "type": "double"}]}}, None: "Record"}}],
    # rand.histogram: Raises a "distribution must be finite" error if any items of <p>distribution</p> are infinite or <c>NaN</c>.
    34071: [{"value": {"distribution": [1.0, "inf", 3.0]}, "domain": lambda distribution: True, "type": {"distribution": {"type": "array", "items": "double"}, None: "int"}}, {"value": {"distribution": [1.0, "-inf", 3.0]}, "domain": lambda distribution: True, "type": {"distribution": {"type": "array", "items": "double"}, None: "int"}}, {"value": {"distribution": [1.0, "nan", 3.0]}, "domain": lambda distribution: True, "type": {"distribution": {"type": "array", "items": "double"}, None: "int"}}, {"value": {"distribution": [{"prob": 1.0}, {"prob": "inf"}, {"prob": 3.0}]}, "domain": lambda distribution: True, "type": {"distribution": {"type": "array", "items": {"type": "record", "name": "Record", "fields": [{"name": "prob", "type": "double"}]}}, None: "Record"}}, {"value": {"distribution": [{"prob": 1.0}, {"prob": "-inf"}, {"prob": 3.0}]}, "domain": lambda distribution: True, "type": {"distribution": {"type": "array", "items": {"type": "record", "name": "Record", "fields": [{"name": "prob", "type": "double"}]}}, None: "Record"}}, {"value": {"distribution": [{"prob": 1.0}, {"prob": "nan"}, {"prob": 3.0}]}, "domain": lambda distribution: True, "type": {"distribution": {"type": "array", "items": {"type": "record", "name": "Record", "fields": [{"name": "prob", "type": "double"}]}}, None: "Record"}}],
    # rand.histogram: Raises a "distribution must be non-negative" error if any items of <p>distribution</p> are negative.
    34072: [{"value": {"distribution": [1.0, -2.0, 3.0]}, "domain": lambda distribution: True, "type": {"distribution": {"type": "array", "items": "double"}, None: "int"}}, {"value": {"distribution": [{"prob": 1.0}, {"prob": -2.0}, {"prob": 3.0}]}, "domain": lambda distribution: True, "type": {"distribution": {"type": "array", "items": {"type": "record", "name": "Record", "fields": [{"name": "prob", "type": "double"}]}}, None: "Record"}}],
    # rand.string: Raises a "size must be positive" error if <p>size</p> is less than or equal to zero.
    34080: [{"value": {"size": 0}, "domain": lambda size: True, "type": {"size": "int", None: "string"}}, {"value": {"size": 0}, "domain": lambda size, population: True, "type": {"size": "int", "population": "string", None: "string"}}, {"value": {"size": 0}, "domain": lambda size, low, high: True, "type": {"size": "int", "low": "int", "high": "int", None: "string"}}, {"value": {"size": -1}, "domain": lambda size: True, "type": {"size": "int", None: "string"}}, {"value": {"size": -1}, "domain": lambda size, population: True, "type": {"size": "int", "population": "string", None: "string"}}, {"value": {"size": -1}, "domain": lambda size, low, high: True, "type": {"size": "int", "low": "int", "high": "int", None: "string"}}],
    # rand.string: Raises a "high must be greater than low" error if <p>high</p> is less than or equal to <p>low</p>.
    34081: [{"value": {"low": 64, "high": 64}, "domain": lambda size, low, high: True, "type": {"size": "int", "low": "int", "high": "int", None: "string"}}, {"value": {"low": 64, "high": 63}, "domain": lambda size, low, high: True, "type": {"size": "int", "low": "int", "high": "int", None: "string"}}],
    # rand.string: Raises an "invalid char" error if <p>low</p> is less than 1 or greater than <c>0xD800</c> or if <p>high</p> is less than 1 or greater than <c>0xD800</c>.
    34082: [{"value": {"low": 0, "high": 64}, "domain": lambda size, low, high: True, "type": {"size": "int", "low": "int", "high": "int", None: "string"}}, {"value": {"low": 64, "high": 55297}, "domain": lambda size, low, high: True, "type": {"size": "int", "low": "int", "high": "int", None: "string"}}],
    # rand.bytes: Raises a "size must be positive" error if <p>size</p> is less than or equal to zero.
    34090: [{"value": {"size": 0}, "domain": lambda size: True, "type": {"size": "int", None: "bytes"}}, {"value": {"size": 0}, "domain": lambda size, population: True, "type": {"size": "int", "population": "bytes", None: "bytes"}}, {"value": {"size": 0}, "domain": lambda size, low, high: True, "type": {"size": "int", "low": "int", "high": "int", None: "bytes"}}, {"value": {"size": -1}, "domain": lambda size: True, "type": {"size": "int", None: "bytes"}}, {"value": {"size": -1}, "domain": lambda size, population: True, "type": {"size": "int", "population": "bytes", None: "bytes"}}, {"value": {"size": -1}, "domain": lambda size, low, high: True, "type": {"size": "int", "low": "int", "high": "int", None: "bytes"}}],
    # rand.bytes: Raises a "high must be greater than low" error if <p>high</p> is less than or equal to <p>low</p>.
    34091: [{"value": {"low": 64, "high": 64}, "domain": lambda size, low, high: True, "type": {"size": "int", "low": "int", "high": "int", None: "bytes"}}, {"value": {"low": 64, "high": 63}, "domain": lambda size, low, high: True, "type": {"size": "int", "low": "int", "high": "int", None: "bytes"}}],
    # rand.bytes: Raises an "invalid byte" error if <p>low</p> is less than 0 or greater than 255 or if <p>high</p> is less than 0 or greater than 256.
    34092: [{"value": {"low": -1, "high": 64}, "domain": lambda size, low, high: True, "type": {"size": "int", "low": "int", "high": "int", None: "bytes"}}, {"value": {"low": 64, "high": 257}, "domain": lambda size, low, high: True, "type": {"size": "int", "low": "int", "high": "int", None: "bytes"}}],
    # s.hex: If <p>width</p> is negative and <p>zeroPad</p> is <c>true</c>, a "negative width cannot be used with zero-padding" error is raised.
    39110: [{"value": {"width": -1, "zeroPad": True}, "domain": lambda x, width, zeroPad: True, "type": {"x": "long", "width": "int", "zeroPad": "boolean", None: "string"}}],
    # s.hex: If <p>x</p> is negative, a "negative number" error is raised.
    39111: [{"value": {"x": -1}, "domain": lambda x: True, "type": {"x": "long", None: "string"}}, {"value": {"x": -1}, "domain": lambda x, width, zeroPad: True, "type": {"x": "long", "width": "int", "zeroPad": "boolean", None: "string"}}],
    # s.int: If <p>width</p> is negative and <p>zeroPad</p> is <c>true</c>, a "negative width cannot be used with zero-padding" error is raised.
    39240: [{"value": {"width": -1, "zeroPad": True}, "domain": lambda x, width, zeroPad: True, "type": {"x": "long", "width": "int", "zeroPad": "boolean", None: "string"}}],
    # s.number: If <p>precision</p> is provided and is less than zero, a "negative precision" error is raised.
    39121: [{"value": {"precision": {"int": -1}}, "domain": lambda x, width, precision: True, "type": {"x": "double", "width": ["int", "null"], "precision": ["int", "null"], None: "string"}}, {"value": {"precision": {"int": -1}}, "domain": lambda x, width, precision, minNoExp, maxNoExp: True, "type": {"x": "double", "width": ["int", "null"], "precision": ["int", "null"], "minNoExp": "double", "maxNoExp": "double", None: "string"}}],
    # re.index: If <p>pattern</p> is not a valid regular expression, a "bad pattern" error is raised.
    35000: [{"value": {"pattern": r"\1"}, "domain": lambda haystack, pattern: True, "type": {"haystack": "string", "pattern": "string", None: {"type": "array", "items": "int"}}}, {"value": {"pattern": base64.b64encode(r"\1")}, "domain": lambda haystack, pattern: True, "type": {"haystack": "bytes", "pattern": "bytes", None: {"type": "array", "items": "int"}}}],
    # re.contains: If <p>pattern</p> is not a valid regular expression, a "bad pattern" error is raised.
    35010: [{"value": {"pattern": r"\1"}, "domain": lambda haystack, pattern: True, "type": {"haystack": "string", "pattern": "string", None: "boolean"}}, {"value": {"pattern": base64.b64encode(r"\1")}, "domain": lambda haystack, pattern: True, "type": {"haystack": "bytes", "pattern": "bytes", None: "boolean"}}],
    # re.count: If <p>pattern</p> is not a valid regular expression, a "bad pattern" error is raised.
    35020: [{"value": {"pattern": r"\1"}, "domain": lambda haystack, pattern: True, "type": {"haystack": "string", "pattern": "string", None: "int"}}, {"value": {"pattern": base64.b64encode(r"\1")}, "domain": lambda haystack, pattern: True, "type": {"haystack": "bytes", "pattern": "bytes", None: "int"}}],
    # re.rindex: If <p>pattern</p> is not a valid regular expression, a "bad pattern" error is raised.
    35030: [{"value": {"pattern": r"\1"}, "domain": lambda haystack, pattern: True, "type": {"haystack": "string", "pattern": "string", None: {"type": "array", "items": "int"}}}, {"value": {"pattern": base64.b64encode(r"\1")}, "domain": lambda haystack, pattern: True, "type": {"haystack": "bytes", "pattern": "bytes", None: {"type": "array", "items": "int"}}}],
    # re.groups: If <p>pattern</p> is not a valid regular expression, a "bad pattern" error is raised.
    35040: [{"value": {"pattern": r"\1"}, "domain": lambda haystack, pattern: True, "type": {"haystack": "string", "pattern": "string", None: {"type": "array", "items": {"type": "array", "items": "int"}}}}, {"value": {"pattern": base64.b64encode(r"\1")}, "domain": lambda haystack, pattern: True, "type": {"haystack": "bytes", "pattern": "bytes", None: {"type": "array", "items": {"type": "array", "items": "int"}}}}],
    # re.indexall: If <p>pattern</p> is not a valid regular expression, a "bad pattern" error is raised.
    35050: [{"value": {"pattern": r"\1"}, "domain": lambda haystack, pattern: True, "type": {"haystack": "string", "pattern": "string", None: {"type": "array", "items": {"type": "array", "items": "int"}}}}, {"value": {"pattern": base64.b64encode(r"\1")}, "domain": lambda haystack, pattern: True, "type": {"haystack": "bytes", "pattern": "bytes", None: {"type": "array", "items": {"type": "array", "items": "int"}}}}],
    # re.findall: If <p>pattern</p> is not a valid regular expression, a "bad pattern" error is raised.
    35060: [{"value": {"pattern": r"\1"}, "domain": lambda pattern, haystack: True, "type": {"pattern": "string", "haystack": "string", None: {"type": "array", "items": "string"}}}, {"value": {"pattern": base64.b64encode(r"\1")}, "domain": lambda pattern, haystack: True, "type": {"pattern": "bytes", "haystack": "bytes", None: {"type": "array", "items": "bytes"}}}],
    # re.findfirst: If <p>pattern</p> is not a valid regular expression, a "bad pattern" error is raised.
    35070: [{"value": {"pattern": r"\1"}, "domain": lambda haystack, pattern: True, "type": {"haystack": "string", "pattern": "string", None: ["string", "null"]}}, {"value": {"pattern": base64.b64encode(r"\1")}, "domain": lambda haystack, pattern: True, "type": {"haystack": "bytes", "pattern": "bytes", None: ["bytes", "null"]}}],
    # re.findgroupsfirst: If <p>pattern</p> is not a valid regular expression, a "bad pattern" error is raised.
    35080: [{"value": {"pattern": r"\1"}, "domain": lambda haystack, pattern: True, "type": {"haystack": "string", "pattern": "string", None: {"type": "array", "items": "string"}}}, {"value": {"pattern": base64.b64encode(r"\1")}, "domain": lambda haystack, pattern: True, "type": {"haystack": "bytes", "pattern": "bytes", None: {"type": "array", "items": "bytes"}}}],
    # re.findgroupsall: If <p>pattern</p> is not a valid regular expression, a "bad pattern" error is raised.
    35090: [{"value": {"pattern": r"\1"}, "domain": lambda haystack, pattern: True, "type": {"haystack": "string", "pattern": "string", None: {"type": "array", "items": {"type": "array", "items": "string"}}}}, {"value": {"pattern": base64.b64encode(r"\1")}, "domain": lambda haystack, pattern: True, "type": {"haystack": "bytes", "pattern": "bytes", None: {"type": "array", "items": {"type": "array", "items": "bytes"}}}}],
    # re.groupsall: If <p>pattern</p> is not a valid regular expression, a "bad pattern" error is raised.
    35100: [{"value": {"pattern": r"\1"}, "domain": lambda haystack, pattern: True, "type": {"haystack": "string", "pattern": "string", None: {"type": "array", "items": {"type": "array", "items": {"type": "array", "items": "int"}}}}}, {"value": {"pattern": base64.b64encode(r"\1")}, "domain": lambda haystack, pattern: True, "type": {"haystack": "bytes", "pattern": "bytes", None: {"type": "array", "items": {"type": "array", "items": {"type": "array", "items": "int"}}}}}],
    # re.replacefirst: If <p>pattern</p> is not a valid regular expression, a "bad pattern" error is raised.
    35110: [{"value": {"pattern": r"\1"}, "domain": lambda haystack, pattern, replacement: True, "type": {"haystack": "string", "pattern": "string", "replacement": "string", None: "string"}}, {"value": {"pattern": base64.b64encode(r"\1")}, "domain": lambda haystack, pattern, replacement: True, "type": {"haystack": "bytes", "pattern": "bytes", "replacement": "bytes", None: "bytes"}}],
    # re.replacelast: If <p>pattern</p> is not a valid regular expression, a "bad pattern" error is raised.
    35120: [{"value": {"pattern": r"\1"}, "domain": lambda haystack, pattern, replacement: True, "type": {"haystack": "string", "pattern": "string", "replacement": "string", None: "string"}}, {"value": {"pattern": base64.b64encode(r"\1")}, "domain": lambda haystack, pattern, replacement: True, "type": {"haystack": "bytes", "pattern": "bytes", "replacement": "bytes", None: "bytes"}}],
    # re.split: If <p>pattern</p> is not a valid regular expression, a "bad pattern" error is raised.
    35130: [{"value": {"pattern": r"\1"}, "domain": lambda haystack, pattern: True, "type": {"haystack": "string", "pattern": "string", None: {"type": "array", "items": "string"}}}, {"value": {"pattern": base64.b64encode(r"\1")}, "domain": lambda haystack, pattern: True, "type": {"haystack": "bytes", "pattern": "bytes", None: {"type": "array", "items": "bytes"}}}],
    # re.replaceall: If <p>pattern</p> is not a valid regular expression, a "bad pattern" error is raised.
    35140: [{"value": {"pattern": r"\1"}, "domain": lambda haystack, pattern, replacement: True, "type": {"haystack": "string", "pattern": "string", "replacement": "string", None: "string"}}, {"value": {"pattern": base64.b64encode(r"\1")}, "domain": lambda haystack, pattern, replacement: True, "type": {"haystack": "bytes", "pattern": "bytes", "replacement": "bytes", None: "bytes"}}],
    # parse.int: Raises "not an integer" if the string does not conform to "<c>[-+]?[0-9a-z]+</c>" or the number it evaluates to is too large to represent as a 32-bit integer or uses characters as large as or larger than <p>base</p> ('0' through '9' encode 0 through 9 and 'a' through 'z' encode 10 through 35).
    33000: [{"value": {"str": "   12.3   ", "base": 10}, "domain": lambda str, base: True, "type": {"str": "string", "base": "int", None: "int"}}, {"value": {"str": "4294967297", "base": 10}, "domain": lambda str, base: True, "type": {"str": "string", "base": "int", None: "int"}}, {"value": {"str": "12a", "base": 10}, "domain": lambda str, base: True, "type": {"str": "string", "base": "int", None: "int"}}],
    # parse.int: Raises "base out of range" if <p>base</p> is less than 2 or greater than 36.
    33001: [{"value": {"base": 1}, "domain": lambda str, base: True, "type": {"str": "string", "base": "int", None: "int"}}, {"value": {"base": 37}, "domain": lambda str, base: True, "type": {"str": "string", "base": "int", None: "int"}}],
    # parse.long: Raises "not a long integer" if the string does not conform to "<c>[-+]?[0-9a-z]+</c>" or the number it evaluates to is too large to represent as a 64-bit integer or uses characters as large as or larger than <p>base</p> ('0' through '9' encode 0 through 9 and 'a' through 'z' encode 10 through 35).
    33010: [{"value": {"str": "   12.3   ", "base": 10}, "domain": lambda str, base: True, "type": {"str": "string", "base": "int", None: "long"}}, {"value": {"str": "18446744073709551617", "base": 10}, "domain": lambda str, base: True, "type": {"str": "string", "base": "int", None: "long"}}, {"value": {"str": "12a", "base": 10}, "domain": lambda str, base: True, "type": {"str": "string", "base": "int", None: "long"}}],
    # parse.long: Raises "base out of range" if <p>base</p> is less than 2 or greater than 36.
    33011: [{"value": {"base": 1}, "domain": lambda str, base: True, "type": {"str": "string", "base": "int", None: "long"}}, {"value": {"base": 37}, "domain": lambda str, base: True, "type": {"str": "string", "base": "int", None: "long"}}],
    # parse.float: Raises "not a single-precision float" if the string does not conform to "<c>[-+]?[0-9]+([eE][-+]?[0-9]+)?</c>".
    33020: [{"value": {"str": "   12f3   "}, "domain": lambda str: True, "type": {"str": "string", None: "float"}}, {"value": {"str": "3.14e12e13"}, "domain": lambda str: True, "type": {"str": "string", None: "float"}}],
    # parse.double: Raises "not a double-precision float" if the string does not conform to "<c>[-+]?[0-9]+([eE][-+]?[0-9]+)?</c>".
    33030: [{"value": {"str": "   12f3   "}, "domain": lambda str: True, "type": {"str": "string", None: "double"}}, {"value": {"str": "3.14e12e13"}, "domain": lambda str: True, "type": {"str": "string", None: "double"}}],
    # cast.signed: If <p>bits</p> is less than 2 or greater than 64, an "unrepresentable unsigned number" error is raised.
    17000: [{"value": {"bits": 1}, "domain": lambda x, bits: True, "type": {"x": "long", "bits": "int", None: "long"}}, {"value": {"bits": 0}, "domain": lambda x, bits: True, "type": {"x": "long", "bits": "int", None: "long"}}, {"value": {"bits": -1}, "domain": lambda x, bits: True, "type": {"x": "long", "bits": "int", None: "long"}}, {"value": {"bits": 65}, "domain": lambda x, bits: True, "type": {"x": "long", "bits": "int", None: "long"}}],
    # cast.unsigned: If <p>bits</p> is less than 1 or greater than 63, an "unrepresentable unsigned number" error is raised.
    17010: [{"value": {"bits": 0}, "domain": lambda x, bits: True, "type": {"x": "long", "bits": "int", None: "long"}}, {"value": {"bits": -1}, "domain": lambda x, bits: True, "type": {"x": "long", "bits": "int", None: "long"}}, {"value": {"bits": 64}, "domain": lambda x, bits: True, "type": {"x": "long", "bits": "int", None: "long"}}],
    # cast.int: Results outside of -2147483648 and 2147483647 (inclusive) produce an "int overflow" runtime error.
    17020: [{"value": {"x": 2147483648}, "domain": lambda x: True, "type": {"x": "long", None: "int"}}, {"value": {"x": 2247483658}, "domain": lambda x: True, "type": {"x": "float", None: "int"}}, {"value": {"x": 2147483648}, "domain": lambda x: True, "type": {"x": "double", None: "int"}}],
    # cast.long: Results outside of -9223372036854775808 and 9223372036854775807 (inclusive) produce a "long overflow" runtime error.
    17030: [{"value": {"x": 9323372036854775808}, "domain": lambda x: True, "type": {"x": "float", None: "long"}}, {"value": {"x": 9223372036954775808}, "domain": lambda x: True, "type": {"x": "double", None: "long"}}],
    # a.head: If <p>a</p> is empty, an "empty array" runtime error is raised.
    15020: [{"value": {"a": []}, "domain": lambda a: True, "type": {"a": {"type": "array", "items": "int"}, None: "int"}}],
    # a.tail: If <p>a</p> is empty, an "empty array" runtime error is raised.
    15030: [{"value": {"a": []}, "domain": lambda a: True, "type": {"a": {"type": "array", "items": "int"}, None: {"type": "array", "items": "int"}}}],
    # a.last: If <p>a</p> is empty, an "empty array" runtime error is raised.
    15040: [{"value": {"a": []}, "domain": lambda a: True, "type": {"a": {"type": "array", "items": "int"}, None: "int"}}],
    # a.init: If <p>a</p> is empty, an "empty array" runtime error is raised.
    15050: [{"value": {"a": []}, "domain": lambda a: True, "type": {"a": {"type": "array", "items": "int"}, None: {"type": "array", "items": "int"}}}],
    # a.cycle: If <p>maxLength</p> is less than 0, this function raises a "maxLength out of range" error.
    15150: [{"value": {"maxLength": -1}, "domain": lambda a, item, maxLength: True, "type": {"a": {"type": "array", "items": "int"}, "item": "int", "maxLength": "int", None: {"type": "array", "items": "int"}}}],
    # a.insert: If <p>index</p> is beyond the range of <p>a</p>, an "index out of range" runtime error is raised.
    15160: [{"value": {"a": [1, 2, 3], "index": 3}, "domain": lambda a, index, item: True, "type": {"a": {"type": "array", "items": "int"}, "index": "int", "item": "int", None: {"type": "array", "items": "int"}}}, {"value": {"a": [1, 2, 3], "index": -4}, "domain": lambda a, index, item: True, "type": {"a": {"type": "array", "items": "int"}, "index": "int", "item": "int", None: {"type": "array", "items": "int"}}}],
    # a.replace: If <p>index</p> is beyond the range of <p>a</p>, an "index out of range" runtime error is raised.
    15170: [{"value": {"a": [1, 2, 3], "index": 3}, "domain": lambda a, index, item: True, "type": {"a": {"type": "array", "items": "int"}, "index": "int", "item": "int", None: {"type": "array", "items": "int"}}}, {"value": {"a": [1, 2, 3], "index": -4}, "domain": lambda a, index, item: True, "type": {"a": {"type": "array", "items": "int"}, "index": "int", "item": "int", None: {"type": "array", "items": "int"}}}],
    # a.remove: If <p>index</p> is beyond the range of <p>a</p>, an "index out of range" runtime error is raised.
    15180: [{"value": {"a": [1, 2, 3], "index": 3}, "domain": lambda a, index: True, "type": {"a": {"type": "array", "items": "int"}, "index": "int", None: {"type": "array", "items": "int"}}}, {"value": {"a": [1, 2, 3], "index": -4}, "domain": lambda a, index: True, "type": {"a": {"type": "array", "items": "int"}, "index": "int", None: {"type": "array", "items": "int"}}}],
    # a.rotate: If <p>steps</p> is less than zero, a "steps out of range" error is raised.
    15190: [{"value": {"steps": -1}, "domain": lambda a, steps: True, "type": {"a": {"type": "array", "items": "int"}, "steps": "int", None: {"type": "array", "items": "int"}}}],
    # a.max: If <p>a</p> is empty, an "empty array" runtime error is raised.
    15240: [{"value": {"a": []}, "domain": lambda a: True, "type": {"a": {"type": "array", "items": "int"}, None: "int"}}],
    # a.min: If <p>a</p> is empty, an "empty array" runtime error is raised.
    15250: [{"value": {"a": []}, "domain": lambda a: True, "type": {"a": {"type": "array", "items": "int"}, None: "int"}}],
    # a.maxLT: If <p>a</p> is empty, an "empty array" runtime error is raised.
    15260: [{"value": {"a": []}, "domain": lambda a, lessThan: True, "type": {"a": {"type": "array", "items": "int"}, "lessThan": {"params": ["int", "int"], "ret": "boolean"}, None: "int"}}],
    # a.minLT: If <p>a</p> is empty, an "empty array" runtime error is raised.
    15270: [{"value": {"a": []}, "domain": lambda a, lessThan: True, "type": {"a": {"type": "array", "items": "int"}, "lessThan": {"params": ["int", "int"], "ret": "boolean"}, None: "int"}}],
    # a.maxN: If <p>a</p> is empty, an "empty array" runtime error is raised.
    15280: [{"value": {"a": []}, "domain": lambda a, n: True, "type": {"a": {"type": "array", "items": "int"}, "n": "int", None: {"type": "array", "items": "int"}}}],
    # a.maxN: If <p>n</p> is negative, an "n < 0" runtime error is raised.
    15281: [{"value": {"n": -1}, "domain": lambda a, n: True, "type": {"a": {"type": "array", "items": "int"}, "n": "int", None: {"type": "array", "items": "int"}}}],
    # a.minN: If <p>a</p> is empty, an "empty array" runtime error is raised.
    15290: [{"value": {"a": []}, "domain": lambda a, n: True, "type": {"a": {"type": "array", "items": "int"}, "n": "int", None: {"type": "array", "items": "int"}}}],
    # a.minN: If <p>n</p> is negative, an "n < 0" runtime error is raised.
    15291: [{"value": {"n": -1}, "domain": lambda a, n: True, "type": {"a": {"type": "array", "items": "int"}, "n": "int", None: {"type": "array", "items": "int"}}}],
    # a.maxNLT: If <p>a</p> is empty, an "empty array" runtime error is raised.
    15300: [{"value": {"a": []}, "domain": lambda a, n, lessThan: True, "type": {"a": {"type": "array", "items": "int"}, "n": "int", "lessThan": {"params": ["int", "int"], "ret": "boolean"}, None: {"type": "array", "items": "int"}}}],
    # a.maxNLT: If <p>n</p> is negative, an "n < 0" runtime error is raised.
    15301: [{"value": {"n": -1}, "domain": lambda a, n, lessThan: True, "type": {"a": {"type": "array", "items": "int"}, "n": "int", "lessThan": {"params": ["int", "int"], "ret": "boolean"}, None: {"type": "array", "items": "int"}}}],
    # a.minNLT: If <p>a</p> is empty, an "empty array" runtime error is raised.
    15310: [{"value": {"a": []}, "domain": lambda a, n, lessThan: True, "type": {"a": {"type": "array", "items": "int"}, "n": "int", "lessThan": {"params": ["int", "int"], "ret": "boolean"}, None: {"type": "array", "items": "int"}}}],
    # a.minNLT: If <p>n</p> is negative, an "n < 0" runtime error is raised.
    15311: [{"value": {"n": -1}, "domain": lambda a, n, lessThan: True, "type": {"a": {"type": "array", "items": "int"}, "n": "int", "lessThan": {"params": ["int", "int"], "ret": "boolean"}, None: {"type": "array", "items": "int"}}}],
    # a.argmax: If <p>a</p> is empty, an "empty array" runtime error is raised.
    15320: [{"value": {"a": []}, "domain": lambda a: True, "type": {"a": {"type": "array", "items": "int"}, None: "int"}}],
    # a.argmin: If <p>a</p> is empty, an "empty array" runtime error is raised.
    15330: [{"value": {"a": []}, "domain": lambda a: True, "type": {"a": {"type": "array", "items": "int"}, None: "int"}}],
    # a.argmaxLT: If <p>a</p> is empty, an "empty array" runtime error is raised.
    15340: [{"value": {"a": []}, "domain": lambda a, lessThan: True, "type": {"a": {"type": "array", "items": "int"}, "lessThan": {"params": ["int", "int"], "ret": "boolean"}, None: "int"}}],
    # a.argminLT: If <p>a</p> is empty, an "empty array" runtime error is raised.
    15350: [{"value": {"a": []}, "domain": lambda a, lessThan: True, "type": {"a": {"type": "array", "items": "int"}, "lessThan": {"params": ["int", "int"], "ret": "boolean"}, None: "int"}}],
    # a.argmaxN: If <p>a</p> is empty, an "empty array" runtime error is raised.
    15360: [{"value": {"a": []}, "domain": lambda a, n: True, "type": {"a": {"type": "array", "items": "int"}, "n": "int", None: {"type": "array", "items": "int"}}}],
    # a.argmaxN: If <p>n</p> is negative, an "n < 0" runtime error is raised.
    15361: [{"value": {"n": -1}, "domain": lambda a, n: True, "type": {"a": {"type": "array", "items": "int"}, "n": "int", None: {"type": "array", "items": "int"}}}],
    # a.argminN: If <p>a</p> is empty, an "empty array" runtime error is raised.
    15370: [{"value": {"a": []}, "domain": lambda a, n: True, "type": {"a": {"type": "array", "items": "int"}, "n": "int", None: {"type": "array", "items": "int"}}}],
    # a.argminN: If <p>n</p> is negative, an "n < 0" runtime error is raised.
    15371: [{"value": {"n": -1}, "domain": lambda a, n: True, "type": {"a": {"type": "array", "items": "int"}, "n": "int", None: {"type": "array", "items": "int"}}}],
    # a.argmaxNLT: If <p>a</p> is empty, an "empty array" runtime error is raised.
    15380: [{"value": {"a": []}, "domain": lambda a, n, lessThan: True, "type": {"a": {"type": "array", "items": "int"}, "n": "int", "lessThan": {"params": ["int", "int"], "ret": "boolean"}, None: {"type": "array", "items": "int"}}}],
    # a.argmaxNLT: If <p>n</p> is negative, an "n < 0" runtime error is raised.
    15381: [{"value": {"n": -1}, "domain": lambda a, n, lessThan: True, "type": {"a": {"type": "array", "items": "int"}, "n": "int", "lessThan": {"params": ["int", "int"], "ret": "boolean"}, None: {"type": "array", "items": "int"}}}],
    # a.argminNLT: If <p>a</p> is empty, an "empty array" runtime error is raised.
    15390: [{"value": {"a": []}, "domain": lambda a, n, lessThan: True, "type": {"a": {"type": "array", "items": "int"}, "n": "int", "lessThan": {"params": ["int", "int"], "ret": "boolean"}, None: {"type": "array", "items": "int"}}}],
    # a.argminNLT: If <p>n</p> is negative, an "n < 0" runtime error is raised.
    15391: [{"value": {"n": -1}, "domain": lambda a, n, lessThan: True, "type": {"a": {"type": "array", "items": "int"}, "n": "int", "lessThan": {"params": ["int", "int"], "ret": "boolean"}, None: {"type": "array", "items": "int"}}}],
    # a.sum: If the array items have integer type and the final result is too large or small to be represented as an integer, an "int overflow" error is raised.
    15400: [{"value": {"a": [1073741823, 1073741823, 1073741823]}, "domain": lambda a: True, "type": {"a": {"type": "array", "items": "int"}, None: "int"}}],
    # a.sum: If the array items have long integer type and the final result is too large or small to be represented as a long integer, an "long overflow" error is raised.
    15401: [{"value": {"a": [4611686018427387903, 4611686018427387903, 4611686018427387903]}, "domain": lambda a: True, "type": {"a": {"type": "array", "items": "long"}, None: "long"}}],
    # a.product: If the array items have integer type and the final result is too large or small to be represented as an integer, an "int overflow" error is raised.
    15410: [{"value": {"a": [1073741823, 3]}, "domain": lambda a: True, "type": {"a": {"type": "array", "items": "int"}, None: "int"}}],
    # a.product: If the array items have long integer type and the final result is too large or small to be represented as a long integer, an "long overflow" error is raised.
    15411: [{"value": {"a": [4611686018427387903, 3]}, "domain": lambda a: True, "type": {"a": {"type": "array", "items": "long"}, None: "long"}}],
    # a.median: If <p>a</p> is empty, an "empty array" runtime error is raised.
    15450: [{"value": {"a": []}, "domain": lambda a: True, "type": {"a": {"type": "array", "items": "int"}, None: "int"}}],
    # a.ntile: If <p>a</p> is empty, an "empty array" runtime error is raised.
    15460: [{"value": {"a": []}, "domain": lambda a, p: True, "type": {"a": {"type": "array", "items": "int"}, "p": "double", None: "int"}}],
    # a.ntile: If <p>p</p> is NaN, this function raises a "p not a number" error.
    15461: [{"value": {"p": float("nan")}, "domain": lambda a, p: True, "type": {"a": {"type": "array", "items": "int"}, "p": "double", None: "int"}}],
    # a.mode: If <p>a</p> is empty, an "empty array" runtime error is raised.
    15470: [{"value": {"a": []}, "domain": lambda a: True, "type": {"a": {"type": "array", "items": "int"}, None: "int"}}],
    # a.zipmap: Raises a "misaligned arrays" error if <p>a</p>, <p>b</p>, <p>c</p>, <p>d</p> do not all have the same length.
    15650: [{"value": {"a": [1, 2, 3], "b": [1, 2]}, "domain": lambda a, b, fcn: True, "type": {"a": {"type": "array", "items": "int"}, "b": {"type": "array", "items": "int"}, "fcn": {"params": ["int", "int"], "ret": "int"}, None: {"type": "array", "items": "int"}}}, {"value": {"a": [1, 2, 3], "b": [1, 2, 3], "c": [1, 2]}, "domain": lambda a, b, c, fcn: True, "type": {"a": {"type": "array", "items": "int"}, "b": {"type": "array", "items": "int"}, "c": {"type": "array", "items": "int"}, "fcn": {"params": ["int", "int", "int"], "ret": "int"}, None: {"type": "array", "items": "int"}}}, {"value": {"a": [1, 2, 3], "b": [1, 2, 3], "c": [1, 2, 3], "d": [1, 2]}, "domain": lambda a, b, c, d, fcn: True, "type": {"a": {"type": "array", "items": "int"}, "b": {"type": "array", "items": "int"}, "c": {"type": "array", "items": "int"}, "d": {"type": "array", "items": "int"}, "fcn": {"params": ["int", "int", "int", "int"], "ret": "int"}, None: {"type": "array", "items": "int"}}}],
    # a.zipmapWithIndex: Raises a "misaligned arrays" error if <p>a</p>, <p>b</p>, <p>c</p>, <p>d</p> do not all have the same length.
    15660: [{"value": {"a": [1, 2, 3], "b": [1, 2]}, "domain": lambda a, b, fcn: True, "type": {"a": {"type": "array", "items": "int"}, "b": {"type": "array", "items": "int"}, "fcn": {"params": ["int", "int", "int"], "ret": "int"}, None: {"type": "array", "items": "int"}}}, {"value": {"a": [1, 2, 3], "b": [1, 2, 3], "c": [1, 2]}, "domain": lambda a, b, c, fcn: True, "type": {"a": {"type": "array", "items": "int"}, "b": {"type": "array", "items": "int"}, "c": {"type": "array", "items": "int"}, "fcn": {"params": ["int", "int", "int", "int"], "ret": "int"}, None: {"type": "array", "items": "int"}}}, {"value": {"a": [1, 2, 3], "b": [1, 2, 3], "c": [1, 2, 3], "d": [1, 2]}, "domain": lambda a, b, c, d, fcn: True, "type": {"a": {"type": "array", "items": "int"}, "b": {"type": "array", "items": "int"}, "c": {"type": "array", "items": "int"}, "d": {"type": "array", "items": "int"}, "fcn": {"params": ["int", "int", "int", "int", "int"], "ret": "int"}, None: {"type": "array", "items": "int"}}}],
    # a.slidingWindow: If <p>size</p> is non-positive, a "size < 1" runtime error is raised.
    15770: [{"value": {"size": 0}, "domain": lambda a, size, step: True, "type": {"a": {"type": "array", "items": "int"}, "size": "int", "step": "int", None: {"type": "array", "items": {"type": "array", "items": "int"}}}}, {"value": {"size": -1}, "domain": lambda a, size, step: True, "type": {"a": {"type": "array", "items": "int"}, "size": "int", "step": "int", None: {"type": "array", "items": {"type": "array", "items": "int"}}}}],
    # a.slidingWindow: If <p>step</p> is non-positive, a "step < 1" runtime error is raised.
    15771: [{"value": {"step": 0}, "domain": lambda a, size, step: True, "type": {"a": {"type": "array", "items": "int"}, "size": "int", "step": "int", None: {"type": "array", "items": {"type": "array", "items": "int"}}}}, {"value": {"step": -1}, "domain": lambda a, size, step: True, "type": {"a": {"type": "array", "items": "int"}, "size": "int", "step": "int", None: {"type": "array", "items": {"type": "array", "items": "int"}}}}],
    # a.combinations: If <p>size</p> is non-positive, a "size < 1" runtime error is raised.
    15780: [{"value": {"size": 0}, "domain": lambda a, size: True, "type": {"a": {"type": "array", "items": "int"}, "size": "int", None: {"type": "array", "items": {"type": "array", "items": "int"}}}}, {"value": {"size": -1}, "domain": lambda a, size: True, "type": {"a": {"type": "array", "items": "int"}, "size": "int", None: {"type": "array", "items": {"type": "array", "items": "int"}}}}],
    # map.argmax: If <p>m</p> is empty, an "empty map" runtime error is raised.
    26120: [{"value": {"m": {}}, "domain": lambda m: True, "type": {"m": {"type": "map", "values": "int"}, None: "string"}}],
    # map.argmin: If <p>m</p> is empty, an "empty map" runtime error is raised.
    26130: [{"value": {"m": {}}, "domain": lambda m: True, "type": {"m": {"type": "map", "values": "int"}, None: "string"}}],
    # map.argmaxLT: If <p>m</p> is empty, an "empty map" runtime error is raised.
    26140: [{"value": {"m": {}}, "domain": lambda m, lessThan: True, "type": {"m": {"type": "map", "values": "int"}, "lessThan": {"params": ["int", "int"], "ret": "boolean"}, None: "string"}}],
    # map.argminLT: If <p>m</p> is empty, an "empty map" runtime error is raised.
    26150: [{"value": {"m": {}}, "domain": lambda m, lessThan: True, "type": {"m": {"type": "map", "values": "int"}, "lessThan": {"params": ["int", "int"], "ret": "boolean"}, None: "string"}}],
    # map.argmaxN: If <p>m</p> is empty, an "empty map" runtime error is raised.
    26160: [{"value": {"m": {}}, "domain": lambda m, n: True, "type": {"m": {"type": "map", "values": "int"}, "n": "int", None: {"type": "array", "items": "string"}}}],
    # map.argmaxN: If <p>n</p> is negative, an "n < 0" runtime error is raised.
    26161: [{"value": {"n": -1}, "domain": lambda m, n: True, "type": {"m": {"type": "map", "values": "int"}, "n": "int", None: {"type": "array", "items": "string"}}}],
    # map.argminN: If <p>m</p> is empty, an "empty map" runtime error is raised.
    26170: [{"value": {"m": {}}, "domain": lambda m, n: True, "type": {"m": {"type": "map", "values": "int"}, "n": "int", None: {"type": "array", "items": "string"}}}],
    # map.argminN: If <p>n</p> is negative, an "n < 0" runtime error is raised.
    26171: [{"value": {"n": -1}, "domain": lambda m, n: True, "type": {"m": {"type": "map", "values": "int"}, "n": "int", None: {"type": "array", "items": "string"}}}],
    # map.argmaxNLT: If <p>m</p> is empty, an "empty map" runtime error is raised.
    26180: [{"value": {"m": {}}, "domain": lambda m, n, lessThan: True, "type": {"m": {"type": "map", "values": "int"}, "n": "int", "lessThan": {"params": ["int", "int"], "ret": "boolean"}, None: {"type": "array", "items": "string"}}}],
    # map.argmaxNLT: If <p>n</p> is negative, an "n < 0" runtime error is raised.
    26181: [{"value": {"n": -1}, "domain": lambda m, n, lessThan: True, "type": {"m": {"type": "map", "values": "int"}, "n": "int", "lessThan": {"params": ["int", "int"], "ret": "boolean"}, None: {"type": "array", "items": "string"}}}],
    # map.argminNLT: If <p>m</p> is empty, an "empty map" runtime error is raised.
    26190: [{"value": {"m": {}}, "domain": lambda m, n, lessThan: True, "type": {"m": {"type": "map", "values": "int"}, "n": "int", "lessThan": {"params": ["int", "int"], "ret": "boolean"}, None: {"type": "array", "items": "string"}}}],
    # map.argminNLT: If <p>n</p> is negative, an "n < 0" runtime error is raised.
    26191: [{"value": {"n": -1}, "domain": lambda m, n, lessThan: True, "type": {"m": {"type": "map", "values": "int"}, "n": "int", "lessThan": {"params": ["int", "int"], "ret": "boolean"}, None: {"type": "array", "items": "string"}}}],
    # map.zipmap: Raises a "misaligned maps" error if <p>a</p>, <p>b</p>, <p>c</p>, <p>d</p> do not all have the same keys.
    26370: [{"value": {"a": {"one": 1, "two": 2, "three": 3}, "b": {"one": 1, "two": 2}}, "domain": lambda a, b, fcn: True, "type": {"a": {"type": "map", "values": "int"}, "b": {"type": "map", "values": "int"}, "fcn": {"params": ["int", "int"], "ret": "int"}, None: {"type": "map", "values": "int"}}}, {"value": {"a": {"one": 1, "two": 2, "three": 3}, "b": {"one": 1, "two": 2, "three": 3}, "c": {"one": 1, "two": 2}}, "domain": lambda a, b, c, fcn: True, "type": {"a": {"type": "map", "values": "int"}, "b": {"type": "map", "values": "int"}, "c": {"type": "map", "values": "int"}, "fcn": {"params": ["int", "int", "int"], "ret": "int"}, None: {"type": "map", "values": "int"}}}, {"value": {"a": {"one": 1, "two": 2, "three": 3}, "b": {"one": 1, "two": 2, "three": 3}, "c": {"one": 1, "two": 2, "three": 3}, "d": {"one": 1, "two": 2}}, "domain": lambda a, b, c, d, fcn: True, "type": {"a": {"type": "map", "values": "int"}, "b": {"type": "map", "values": "int"}, "c": {"type": "map", "values": "int"}, "d": {"type": "map", "values": "int"}, "fcn": {"params": ["int", "int", "int", "int"], "ret": "int"}, None: {"type": "map", "values": "int"}}}],
    # map.zipmapWithKey: Raises a "misaligned maps" error if <p>a</p>, <p>b</p>, <p>c</p>, <p>d</p> do not all have the same keys.
    26380: [{"value": {"a": {"one": 1, "two": 2, "three": 3}, "b": {"one": 1, "two": 2}}, "domain": lambda a, b, fcn: True, "type": {"a": {"type": "map", "values": "int"}, "b": {"type": "map", "values": "int"}, "fcn": {"params": ["string", "int", "int"], "ret": "int"}, None: {"type": "map", "values": "int"}}}, {"value": {"a": {"one": 1, "two": 2, "three": 3}, "b": {"one": 1, "two": 2, "three": 3}, "c": {"one": 1, "two": 2}}, "domain": lambda a, b, c, fcn: True, "type": {"a": {"type": "map", "values": "int"}, "b": {"type": "map", "values": "int"}, "c": {"type": "map", "values": "int"}, "fcn": {"params": ["string", "int", "int", "int"], "ret": "int"}, None: {"type": "map", "values": "int"}}}, {"value": {"a": {"one": 1, "two": 2, "three": 3}, "b": {"one": 1, "two": 2, "three": 3}, "c": {"one": 1, "two": 2, "three": 3}, "d": {"one": 1, "two": 2}}, "domain": lambda a, b, c, d, fcn: True, "type": {"a": {"type": "map", "values": "int"}, "b": {"type": "map", "values": "int"}, "c": {"type": "map", "values": "int"}, "d": {"type": "map", "values": "int"}, "fcn": {"params": ["string", "int", "int", "int", "int"], "ret": "int"}, None: {"type": "map", "values": "int"}}}],
    # bytes.decodeAscii: Raises an "invalid bytes" error if the bytes cannot be converted.
    16090: [{"value": {"x": base64.b64encode("\x80")}, "domain": lambda x: True, "type": {"x": "bytes", None: "string"}}],
    # bytes.decodeLatin1: Raises an "invalid bytes" error if the bytes cannot be converted.
    16100: [],
    # bytes.decodeUtf8: Raises an "invalid bytes" error if the bytes cannot be converted.
    16110: [{"value": {"x": base64.b64encode("\x80")}, "domain": lambda x: True, "type": {"x": "bytes", None: "string"}}],
    # bytes.decodeUtf16: Raises an "invalid bytes" error if the bytes cannot be converted.
    16120: [{"value": {"x": base64.b64encode("a")}, "domain": lambda x: True, "type": {"x": "bytes", None: "string"}}],
    # bytes.decodeUtf16be: Raises an "invalid bytes" error if the bytes cannot be converted.
    16130: [{"value": {"x": base64.b64encode("a")}, "domain": lambda x: True, "type": {"x": "bytes", None: "string"}}],
    # bytes.decodeUtf16le: Raises an "invalid bytes" error if the bytes cannot be converted.
    16140: [{"value": {"x": base64.b64encode("a")}, "domain": lambda x: True, "type": {"x": "bytes", None: "string"}}],
    # bytes.encodeAscii: Raises an "invalid string" error if the string cannot be converted.
    16150: [{"value": {"s": u"\u2212"}, "domain": lambda s: True, "type": {"s": "string", None: "bytes"}}],
    # bytes.encodeLatin1: Raises an "invalid string" error if the string cannot be converted.
    16160: [{"value": {"s": u"\u2212"}, "domain": lambda s: True, "type": {"s": "string", None: "bytes"}}],
    # bytes.encodeUtf8: Raises an "invalid string" error if the string cannot be converted.
    16170: [],
    # bytes.encodeUtf16: Raises an "invalid string" error if the string cannot be converted.
    16180: [],
    # bytes.encodeUtf16be: Raises an "invalid string" error if the string cannot be converted.
    16190: [],
    # bytes.encodeUtf16le: Raises an "invalid string" error if the string cannot be converted.
    16200: [],
    # bytes.fromBase64: Raises an "invalid base64" error if the string is not valid base64.
    16220: [{"value": {"s": "..."}, "domain": lambda s: True, "type": {"s": "string", None: "bytes"}}],
    # time.year: Raises "unrecognized timezone string" if <p>zone</p> is not in the Olson 2015f database.
    40000: [{"value": {"zone": "where/ever"}, "domain": lambda ts, zone: True, "type": {"ts": "double", "zone": "string", None: "int"}}],
    # time.year: Raises "timestamp out of range" if <p>ts</p> less than -62135596800 or greater than 253402300799.
    40001: [{"value": {"ts": -62135596801, "zone": "Etc/UTC"}, "domain": lambda ts, zone: True, "type": {"ts": "double", "zone": "string", None: "int"}}, {"value": {"ts": 253402300800, "zone": "Etc/UTC"}, "domain": lambda ts, zone: True, "type": {"ts": "double", "zone": "string", None: "int"}}],
    # time.monthOfYear: Raises "unrecognized timezone string" if <p>zone</p> is not in the Olson 2015f database.
    40010: [{"value": {"zone": "where/ever"}, "domain": lambda ts, zone: True, "type": {"ts": "double", "zone": "string", None: "int"}}],
    # time.monthOfYearyear: Raises "timestamp out of range" if <p>ts</p> less than -62135596800 or greater than 253402300799.
    40011: [{"value": {"ts": -62135596801, "zone": "Etc/UTC"}, "domain": lambda ts, zone: True, "type": {"ts": "double", "zone": "string", None: "int"}}, {"value": {"ts": 253402300800, "zone": "Etc/UTC"}, "domain": lambda ts, zone: True, "type": {"ts": "double", "zone": "string", None: "int"}}],
    # time.dayOfYear: Raises "unrecognized timezone string" if <p>zone</p> is not in the Olson 2015f database.
    40020: [{"value": {"zone": "where/ever"}, "domain": lambda ts, zone: True, "type": {"ts": "double", "zone": "string", None: "int"}}],
    # time.dayOfYear: Raises "timestamp out of range" if <p>ts</p> less than -62135596800 or greater than 253402300799.
    40021: [{"value": {"ts": -62135596801, "zone": "Etc/UTC"}, "domain": lambda ts, zone: True, "type": {"ts": "double", "zone": "string", None: "int"}}, {"value": {"ts": 253402300800, "zone": "Etc/UTC"}, "domain": lambda ts, zone: True, "type": {"ts": "double", "zone": "string", None: "int"}}],
    # time.dayOfMonth: Raises "unrecognized timezone string" if <p>zone</p> is not in the Olson 2015f database.
    40030: [{"value": {"zone": "where/ever"}, "domain": lambda ts, zone: True, "type": {"ts": "double", "zone": "string", None: "int"}}],
    # time.dayOfMonth: Raises "timestamp out of range" if <p>ts</p> less than -62135596800 or greater than 253402300799.
    40031: [{"value": {"ts": -62135596801, "zone": "Etc/UTC"}, "domain": lambda ts, zone: True, "type": {"ts": "double", "zone": "string", None: "int"}}, {"value": {"ts": 253402300800, "zone": "Etc/UTC"}, "domain": lambda ts, zone: True, "type": {"ts": "double", "zone": "string", None: "int"}}],
    # time.dayOfWeek: Raises "unrecognized timezone string" if <p>zone</p> is not in the Olson 2015f database.
    40040: [{"value": {"zone": "where/ever"}, "domain": lambda ts, zone: True, "type": {"ts": "double", "zone": "string", None: "int"}}],
    # time.dayOfWeek: Raises "timestamp out of range" if <p>ts</p> less than -62135596800 or greater than 253402300799.
    40041: [{"value": {"ts": -62135596801, "zone": "Etc/UTC"}, "domain": lambda ts, zone: True, "type": {"ts": "double", "zone": "string", None: "int"}}, {"value": {"ts": 253402300800, "zone": "Etc/UTC"}, "domain": lambda ts, zone: True, "type": {"ts": "double", "zone": "string", None: "int"}}],
    # time.hourOfDay: Raises "unrecognized timezone string" if <p>zone</p> is not in the Olson 2015f database.
    40050: [{"value": {"zone": "where/ever"}, "domain": lambda ts, zone: True, "type": {"ts": "double", "zone": "string", None: "int"}}],
    # time.hourOfDay: Raises "timestamp out of range" if <p>ts</p> less than -62135596800 or greater than 253402300799.
    40051: [{"value": {"ts": -62135596801, "zone": "Etc/UTC"}, "domain": lambda ts, zone: True, "type": {"ts": "double", "zone": "string", None: "int"}}, {"value": {"ts": 253402300800, "zone": "Etc/UTC"}, "domain": lambda ts, zone: True, "type": {"ts": "double", "zone": "string", None: "int"}}],
    # time.minuteOfHour: Raises "unrecognized timezone string" if <p>zone</p> is not in the Olson 2015f database.
    40060: [{"value": {"zone": "where/ever"}, "domain": lambda ts, zone: True, "type": {"ts": "double", "zone": "string", None: "int"}}],
    # time.minuteOfHour: Raises "timestamp out of range" if <p>ts</p> less than -62135596800 or greater than 253402300799.
    40061: [{"value": {"ts": -62135596801, "zone": "Etc/UTC"}, "domain": lambda ts, zone: True, "type": {"ts": "double", "zone": "string", None: "int"}}, {"value": {"ts": 253402300800, "zone": "Etc/UTC"}, "domain": lambda ts, zone: True, "type": {"ts": "double", "zone": "string", None: "int"}}],
    # time.secondOfMinute: Raises "unrecognized timezone string" if <p>zone</p> is not in the Olson 2015f database.
    40070: [{"value": {"zone": "where/ever"}, "domain": lambda ts, zone: True, "type": {"ts": "double", "zone": "string", None: "int"}}],
    # time.secondOfMinute: Raises "timestamp out of range" if <p>ts</p> less than -62135596800 or greater than 253402300799.
    40071: [{"value": {"ts": -62135596801, "zone": "Etc/UTC"}, "domain": lambda ts, zone: True, "type": {"ts": "double", "zone": "string", None: "int"}}, {"value": {"ts": 253402300800, "zone": "Etc/UTC"}, "domain": lambda ts, zone: True, "type": {"ts": "double", "zone": "string", None: "int"}}],
    # time.makeTimestamp: Raises "unrecognized timezone string" if <p>zone</p> is not in the Olson 2015f database.
    40080: [{"value": {"zone": "where/ever"}, "domain": lambda year, month, day, hour, minute, second, millisecond, zone: True, "type": {"year": "int", "month": "int", "day": "int", "hour": "int", "minute": "int", "second": "int", "millisecond": "int", "zone": "string", None: "double"}}],
    # time.makeTimestamp: Raises "timestamp undefined for given parameters" if any one (or more) of the inputs have impossible values.
    40081: [{"value": {"year": 0, "month": 1, "day": 11, "hour": 11, "minute": 11, "second": 11, "millisecond": 11, "zone": ""}, "domain": lambda year, month, day, hour, minute, second, millisecond, zone: True, "type": {"year": "int", "month": "int", "day": "int", "hour": "int", "minute": "int", "second": "int", "millisecond": "int", "zone": "string", None: "double"}}, {"value": {"year": -1, "month": 1, "day": 11, "hour": 11, "minute": 11, "second": 11, "millisecond": 11, "zone": ""}, "domain": lambda year, month, day, hour, minute, second, millisecond, zone: True, "type": {"year": "int", "month": "int", "day": "int", "hour": "int", "minute": "int", "second": "int", "millisecond": "int", "zone": "string", None: "double"}}, {"value": {"year": 10000, "month": 1, "day": 11, "hour": 11, "minute": 11, "second": 11, "millisecond": 11, "zone": ""}, "domain": lambda year, month, day, hour, minute, second, millisecond, zone: True, "type": {"year": "int", "month": "int", "day": "int", "hour": "int", "minute": "int", "second": "int", "millisecond": "int", "zone": "string", None: "double"}}, {"value": {"year": 2015, "month": 0, "day": 11, "hour": 11, "minute": 11, "second": 11, "millisecond": 11, "zone": ""}, "domain": lambda year, month, day, hour, minute, second, millisecond, zone: True, "type": {"year": "int", "month": "int", "day": "int", "hour": "int", "minute": "int", "second": "int", "millisecond": "int", "zone": "string", None: "double"}}, {"value": {"year": 2015, "month": -1, "day": 11, "hour": 11, "minute": 11, "second": 11, "millisecond": 11, "zone": ""}, "domain": lambda year, month, day, hour, minute, second, millisecond, zone: True, "type": {"year": "int", "month": "int", "day": "int", "hour": "int", "minute": "int", "second": "int", "millisecond": "int", "zone": "string", None: "double"}}, {"value": {"year": 2015, "month": 13, "day": 11, "hour": 11, "minute": 11, "second": 11, "millisecond": 11, "zone": ""}, "domain": lambda year, month, day, hour, minute, second, millisecond, zone: True, "type": {"year": "int", "month": "int", "day": "int", "hour": "int", "minute": "int", "second": "int", "millisecond": "int", "zone": "string", None: "double"}}, {"value": {"year": 2015, "month": 11, "day": 0, "hour": 11, "minute": 11, "second": 11, "millisecond": 11, "zone": ""}, "domain": lambda year, month, day, hour, minute, second, millisecond, zone: True, "type": {"year": "int", "month": "int", "day": "int", "hour": "int", "minute": "int", "second": "int", "millisecond": "int", "zone": "string", None: "double"}}, {"value": {"year": 2015, "month": 11, "day": -1, "hour": 11, "minute": 11, "second": 11, "millisecond": 11, "zone": ""}, "domain": lambda year, month, day, hour, minute, second, millisecond, zone: True, "type": {"year": "int", "month": "int", "day": "int", "hour": "int", "minute": "int", "second": "int", "millisecond": "int", "zone": "string", None: "double"}}, {"value": {"year": 2015, "month": 11, "day": 31, "hour": 11, "minute": 11, "second": 11, "millisecond": 11, "zone": ""}, "domain": lambda year, month, day, hour, minute, second, millisecond, zone: True, "type": {"year": "int", "month": "int", "day": "int", "hour": "int", "minute": "int", "second": "int", "millisecond": "int", "zone": "string", None: "double"}}, {"value": {"year": 2015, "month": 11, "day": 32, "hour": 11, "minute": 11, "second": 11, "millisecond": 11, "zone": ""}, "domain": lambda year, month, day, hour, minute, second, millisecond, zone: True, "type": {"year": "int", "month": "int", "day": "int", "hour": "int", "minute": "int", "second": "int", "millisecond": "int", "zone": "string", None: "double"}}, {"value": {"year": 2015, "month": 11, "day": 11, "hour": -1, "minute": 11, "second": 11, "millisecond": 11, "zone": ""}, "domain": lambda year, month, day, hour, minute, second, millisecond, zone: True, "type": {"year": "int", "month": "int", "day": "int", "hour": "int", "minute": "int", "second": "int", "millisecond": "int", "zone": "string", None: "double"}}, {"value": {"year": 2015, "month": 11, "day": 11, "hour": 24, "minute": 11, "second": 11, "millisecond": 11, "zone": ""}, "domain": lambda year, month, day, hour, minute, second, millisecond, zone: True, "type": {"year": "int", "month": "int", "day": "int", "hour": "int", "minute": "int", "second": "int", "millisecond": "int", "zone": "string", None: "double"}}, {"value": {"year": 2015, "month": 11, "day": 11, "hour": 11, "minute": -1, "second": 11, "millisecond": 11, "zone": ""}, "domain": lambda year, month, day, hour, minute, second, millisecond, zone: True, "type": {"year": "int", "month": "int", "day": "int", "hour": "int", "minute": "int", "second": "int", "millisecond": "int", "zone": "string", None: "double"}}, {"value": {"year": 2015, "month": 11, "day": 11, "hour": 11, "minute": 60, "second": 11, "millisecond": 11, "zone": ""}, "domain": lambda year, month, day, hour, minute, second, millisecond, zone: True, "type": {"year": "int", "month": "int", "day": "int", "hour": "int", "minute": "int", "second": "int", "millisecond": "int", "zone": "string", None: "double"}}, {"value": {"year": 2015, "month": 11, "day": 11, "hour": 11, "minute": 11, "second": -1, "millisecond": 11, "zone": ""}, "domain": lambda year, month, day, hour, minute, second, millisecond, zone: True, "type": {"year": "int", "month": "int", "day": "int", "hour": "int", "minute": "int", "second": "int", "millisecond": "int", "zone": "string", None: "double"}}, {"value": {"year": 2015, "month": 11, "day": 11, "hour": 11, "minute": 11, "second": 60, "millisecond": 11, "zone": ""}, "domain": lambda year, month, day, hour, minute, second, millisecond, zone: True, "type": {"year": "int", "month": "int", "day": "int", "hour": "int", "minute": "int", "second": "int", "millisecond": "int", "zone": "string", None: "double"}}, {"value": {"year": 2015, "month": 11, "day": 11, "hour": 11, "minute": 11, "second": 11, "millisecond": -1, "zone": ""}, "domain": lambda year, month, day, hour, minute, second, millisecond, zone: True, "type": {"year": "int", "month": "int", "day": "int", "hour": "int", "minute": "int", "second": "int", "millisecond": "int", "zone": "string", None: "double"}}, {"value": {"year": 2015, "month": 11, "day": 11, "hour": 11, "minute": 11, "second": 11, "millisecond": 1000, "zone": ""}, "domain": lambda year, month, day, hour, minute, second, millisecond, zone: True, "type": {"year": "int", "month": "int", "day": "int", "hour": "int", "minute": "int", "second": "int", "millisecond": "int", "zone": "string", None: "double"}}],
    # time.isSecondOfMinute: Raises "bad time range" if low <m>\mathrm{low} \geq \mathrm{high}</m>.
    40090: [{"value": {"low": 5, "high": 5}, "domain": lambda ts, zone, low, high: True, "type": {"ts": "double", "zone": "string", "low": "double", "high": "double", None: "boolean"}}, {"value": {"low": 5, "high": 4}, "domain": lambda ts, zone, low, high: True, "type": {"ts": "double", "zone": "string", "low": "double", "high": "double", None: "boolean"}}],
    # time.isSecondOfMinute: Raises "unrecognized timezone string" if <p>zone</p> is not in the Olson 2015f database.
    40091: [{"value": {"zone": "where/ever"}, "domain": lambda ts, zone, low, high: True, "type": {"ts": "double", "zone": "string", "low": "double", "high": "double", None: "boolean"}}],
    # time.isSecondOfMinute: Raises "timestamp out of range" if <p>ts</p> less than -62135596800 or greater than 253402300799.
    40092: [{"value": {"ts": -62135596801, "zone": "Etc/UTC"}, "domain": lambda ts, zone, low, high: True, "type": {"ts": "double", "zone": "string", "low": "double", "high": "double", None: "boolean"}}, {"value": {"ts": 253402300800, "zone": "Etc/UTC"}, "domain": lambda ts, zone, low, high: True, "type": {"ts": "double", "zone": "string", "low": "double", "high": "double", None: "boolean"}}],
    # time.isMinuteOfHour: Raises "bad time range" if low <m>\mathrm{low} \geq \mathrm{high}</m>.
    40100: [{"value": {"low": 5, "high": 5}, "domain": lambda ts, zone, low, high: True, "type": {"ts": "double", "zone": "string", "low": "double", "high": "double", None: "boolean"}}, {"value": {"low": 5, "high": 4}, "domain": lambda ts, zone, low, high: True, "type": {"ts": "double", "zone": "string", "low": "double", "high": "double", None: "boolean"}}],
    # time.isMinuteOfHour: Raises "unrecognized timezone string" if <p>zone</p> is not in the Olson 2015f database.
    40101: [{"value": {"zone": "where/ever"}, "domain": lambda ts, zone, low, high: True, "type": {"ts": "double", "zone": "string", "low": "double", "high": "double", None: "boolean"}}],
    # time.isMinuteOfHour: Raises "timestamp out of range" if <p>ts</p> less than -62135596800 or greater than 253402300799.
    40102: [{"value": {"ts": -62135596801, "zone": "Etc/UTC"}, "domain": lambda ts, zone, low, high: True, "type": {"ts": "double", "zone": "string", "low": "double", "high": "double", None: "boolean"}}, {"value": {"ts": 253402300800, "zone": "Etc/UTC"}, "domain": lambda ts, zone, low, high: True, "type": {"ts": "double", "zone": "string", "low": "double", "high": "double", None: "boolean"}}],
    # time.isHourOfDay: Raises "bad time range" if low <m>\mathrm{low} \geq \mathrm{high}</m>.
    40110: [{"value": {"low": 5, "high": 5}, "domain": lambda ts, zone, low, high: True, "type": {"ts": "double", "zone": "string", "low": "double", "high": "double", None: "boolean"}}, {"value": {"low": 5, "high": 4}, "domain": lambda ts, zone, low, high: True, "type": {"ts": "double", "zone": "string", "low": "double", "high": "double", None: "boolean"}}],
    # time.isHourOfDay: Raises "unrecognized timezone string" if <p>zone</p> is not in the Olson 2015f database.
    40111: [{"value": {"zone": "where/ever"}, "domain": lambda ts, zone, low, high: True, "type": {"ts": "double", "zone": "string", "low": "double", "high": "double", None: "boolean"}}],
    # time.isHourOfDay: Raises "timestamp out of range" if <p>ts</p> less than -62135596800 or greater than 253402300799.
    40112: [{"value": {"ts": -62135596801, "zone": "Etc/UTC"}, "domain": lambda ts, zone, low, high: True, "type": {"ts": "double", "zone": "string", "low": "double", "high": "double", None: "boolean"}}, {"value": {"ts": 253402300800, "zone": "Etc/UTC"}, "domain": lambda ts, zone, low, high: True, "type": {"ts": "double", "zone": "string", "low": "double", "high": "double", None: "boolean"}}],
    # time.isDayOfWeek: Raises "bad time range" if low <m>\mathrm{low} \geq \mathrm{high}</m>.
    40120: [{"value": {"low": 5, "high": 5}, "domain": lambda ts, zone, low, high: True, "type": {"ts": "double", "zone": "string", "low": "double", "high": "double", None: "boolean"}}, {"value": {"low": 5, "high": 4}, "domain": lambda ts, zone, low, high: True, "type": {"ts": "double", "zone": "string", "low": "double", "high": "double", None: "boolean"}}],
    # time.isDayOfWeek: Raises "unrecognized timezone string" if <p>zone</p> is not in the Olson 2015f database.
    40121: [{"value": {"zone": "where/ever"}, "domain": lambda ts, zone, low, high: True, "type": {"ts": "double", "zone": "string", "low": "double", "high": "double", None: "boolean"}}],
    # time.isDayOfWeek: Raises "timestamp out of range" if <p>ts</p> less than -62135596800 or greater than 253402300799.
    40122: [{"value": {"ts": -62135596801, "zone": "Etc/UTC"}, "domain": lambda ts, zone, low, high: True, "type": {"ts": "double", "zone": "string", "low": "double", "high": "double", None: "boolean"}}, {"value": {"ts": 253402300800, "zone": "Etc/UTC"}, "domain": lambda ts, zone, low, high: True, "type": {"ts": "double", "zone": "string", "low": "double", "high": "double", None: "boolean"}}],
    # time.isDayOfMonth: Raises "bad time range" if low <m>\mathrm{low} \geq \mathrm{high}</m>.
    40130: [{"value": {"low": 5, "high": 5}, "domain": lambda ts, zone, low, high: True, "type": {"ts": "double", "zone": "string", "low": "double", "high": "double", None: "boolean"}}, {"value": {"low": 5, "high": 4}, "domain": lambda ts, zone, low, high: True, "type": {"ts": "double", "zone": "string", "low": "double", "high": "double", None: "boolean"}}],
    # time.isDayOfMonth: Raises "unrecognized timezone string" if <p>zone</p> is not in the Olson 2015f database.
    40131: [{"value": {"zone": "where/ever"}, "domain": lambda ts, zone, low, high: True, "type": {"ts": "double", "zone": "string", "low": "double", "high": "double", None: "boolean"}}],
    # time.isDayOfMonth: Raises "timestamp out of range" if <p>ts</p> less than -62135596800 or greater than 253402300799.
    40132: [{"value": {"ts": -62135596801, "zone": "Etc/UTC"}, "domain": lambda ts, zone, low, high: True, "type": {"ts": "double", "zone": "string", "low": "double", "high": "double", None: "boolean"}}, {"value": {"ts": 253402300800, "zone": "Etc/UTC"}, "domain": lambda ts, zone, low, high: True, "type": {"ts": "double", "zone": "string", "low": "double", "high": "double", None: "boolean"}}],
    # time.isMonthOfYear: Raises "bad time range" if low <m>\mathrm{low} \geq \mathrm{high}</m>.
    40140: [{"value": {"low": 5, "high": 5}, "domain": lambda ts, zone, low, high: True, "type": {"ts": "double", "zone": "string", "low": "double", "high": "double", None: "boolean"}}, {"value": {"low": 5, "high": 4}, "domain": lambda ts, zone, low, high: True, "type": {"ts": "double", "zone": "string", "low": "double", "high": "double", None: "boolean"}}],
    # time.isMonthOfYear: Raises "unrecognized timezone string" if <p>zone</p> is not in the Olson 2015f database.
    40141: [{"value": {"zone": "where/ever"}, "domain": lambda ts, zone, low, high: True, "type": {"ts": "double", "zone": "string", "low": "double", "high": "double", None: "boolean"}}],
    # time.isMonthOfYear: Raises "timestamp out of range" if <p>ts</p> less than -62135596800 or greater than 253402300799.
    40142: [{"value": {"ts": -62135596801, "zone": "Etc/UTC"}, "domain": lambda ts, zone, low, high: True, "type": {"ts": "double", "zone": "string", "low": "double", "high": "double", None: "boolean"}}, {"value": {"ts": 253402300800, "zone": "Etc/UTC"}, "domain": lambda ts, zone, low, high: True, "type": {"ts": "double", "zone": "string", "low": "double", "high": "double", None: "boolean"}}],
    # time.isDayOfYear: Raises "bad time range" if low <m>\mathrm{low} \geq \mathrm{high}</m>.
    40150: [{"value": {"low": 5, "high": 5}, "domain": lambda ts, zone, low, high: True, "type": {"ts": "double", "zone": "string", "low": "double", "high": "double", None: "boolean"}}, {"value": {"low": 5, "high": 4}, "domain": lambda ts, zone, low, high: True, "type": {"ts": "double", "zone": "string", "low": "double", "high": "double", None: "boolean"}}],
    # time.isDayOfYear: Raises "unrecognized timezone string" if <p>zone</p> is not in the Olson 2015f database.
    40151: [{"value": {"zone": "where/ever"}, "domain": lambda ts, zone, low, high: True, "type": {"ts": "double", "zone": "string", "low": "double", "high": "double", None: "boolean"}}],
    # time.isDayOfYear: Raises "timestamp out of range" if <p>ts</p> less than -62135596800 or greater than 253402300799.
    40152: [{"value": {"ts": -62135596801, "zone": "Etc/UTC"}, "domain": lambda ts, zone, low, high: True, "type": {"ts": "double", "zone": "string", "low": "double", "high": "double", None: "boolean"}}, {"value": {"ts": 253402300800, "zone": "Etc/UTC"}, "domain": lambda ts, zone, low, high: True, "type": {"ts": "double", "zone": "string", "low": "double", "high": "double", None: "boolean"}}],
    # time.isWeekend: Raises "unrecognized timezone string" if <p>zone</p> is not in the Olson 2015f database.
    40160: [{"value": {"zone": "where/ever"}, "domain": lambda ts, zone: True, "type": {"ts": "double", "zone": "string", None: "boolean"}}],
    # time.isWeekend: Raises "timestamp out of range" if <p>ts</p> less than -62135596800 or greater than 253402300799.
    40161: [{"value": {"ts": -62135596801, "zone": "Etc/UTC"}, "domain": lambda ts, zone: True, "type": {"ts": "double", "zone": "string", None: "boolean"}}, {"value": {"ts": 253402300800, "zone": "Etc/UTC"}, "domain": lambda ts, zone: True, "type": {"ts": "double", "zone": "string", None: "boolean"}}],
    # time.isWorkHours: Raises "unrecognized timezone string" if <p>zone</p> is not in the Olson 2015f database.
    40170: [{"value": {"zone": "where/ever"}, "domain": lambda ts, zone: True, "type": {"ts": "double", "zone": "string", None: "boolean"}}],
    # time.isWorkHours: Raises "timestamp out of range" if <p>ts</p> less than -62135596800 or greater than 253402300799.
    40171: [{"value": {"ts": -62135596801, "zone": "Etc/UTC"}, "domain": lambda ts, zone: True, "type": {"ts": "double", "zone": "string", None: "boolean"}}, {"value": {"ts": 253402300800, "zone": "Etc/UTC"}, "domain": lambda ts, zone: True, "type": {"ts": "double", "zone": "string", None: "boolean"}}],
    # impute.errorOnNull: Raises an "encountered null" error if <p>x</p> is <c>null</c>.
    21000: [{"value": {"x": None}, "domain": lambda x: True, "type": {"x": ["int", "null"], None: "int"}}, {"value": {"x": None}, "domain": lambda x: True, "type": {"x": ["string", "null"], None: "string"}}],
    # impute.errorOnNonNum: Raises an "encountered nan" if <p>x</p> is <c>nan</c>.
    21050: [{"value": {"x": "nan"}, "domain": lambda x: True, "type": {"x": "float", None: "float"}}, {"value": {"x": "nan"}, "domain": lambda x: True, "type": {"x": "double", None: "double"}}],
    # impute.errorOnNonNum: Raises an "encountered +inf" if <p>x</p> is positive infinity.
    21051: [{"value": {"x": "inf"}, "domain": lambda x: True, "type": {"x": "float", None: "float"}}, {"value": {"x": "inf"}, "domain": lambda x: True, "type": {"x": "double", None: "double"}}],
    # impute.errorOnNonNum: Raises an "encountered -inf" if <p>x</p> is negative infinity.
    21052: [{"value": {"x": "-inf"}, "domain": lambda x: True, "type": {"x": "float", None: "float"}}, {"value": {"x": "-inf"}, "domain": lambda x: True, "type": {"x": "double", None: "double"}}],
    # interp.bin: If <p>low</p> is greater or equal to <p>high</p>, raises "bad histogram range"
    22000: [{"value": {"low": 3.14, "high": 3.14}, "domain": lambda x, numbins, low, high: True, "type": {"x": "double", "numbins": "int", "low": "double", "high": "double", None: "int"}}, {"value": {"low": 3.14, "high": 2.2}, "domain": lambda x, numbins, low, high: True, "type": {"x": "double", "numbins": "int", "low": "double", "high": "double", None: "int"}}],
    # interp.bin: If <p>numbins</p> is less than <c>1</c> or <p>width</p> is less or equal to <c>0</c>, raises "bad histogram scale"
    22001: [{"value": {"numbins": 0}, "domain": lambda x, numbins, low, high: True, "type": {"x": "double", "numbins": "int", "low": "double", "high": "double", None: "int"}}, {"value": {"numbins": -1}, "domain": lambda x, numbins, low, high: True, "type": {"x": "double", "numbins": "int", "low": "double", "high": "double", None: "int"}}, {"value": {"width": 0}, "domain": lambda x, origin, width: True, "type": {"x": "double", "origin": "double", "width": "double", None: "int"}}, {"value": {"width": -1.1}, "domain": lambda x, origin, width: True, "type": {"x": "double", "origin": "double", "width": "double", None: "int"}}],
    # interp.bin: If the first signature is used, raises "x out of range" if <p>x</p> is less than <p>low</p> or greater or equal to <p>high</p>.
    22002: [{"value": {"x": 2.0, "low": 2.2, "high": 3.14}, "domain": lambda x, numbins, low, high: True, "type": {"x": "double", "numbins": "int", "low": "double", "high": "double", None: "int"}}, {"value": {"x": 3.14, "low": 2.2, "high": 3.14}, "domain": lambda x, numbins, low, high: True, "type": {"x": "double", "numbins": "int", "low": "double", "high": "double", None: "int"}}, {"value": {"x": 3.3, "low": 2.2, "high": 3.14}, "domain": lambda x, numbins, low, high: True, "type": {"x": "double", "numbins": "int", "low": "double", "high": "double", None: "int"}}],
    # interp.nearest: Raises a "table must have at least one entry" error if <p>table</p> has fewer than one entry.
    22010: [{"value": {"table": []}, "domain": lambda x, table: True, "type": {"x": "double", "table": {"type": "array", "items": {"type": "record", "name": "Record", "fields": [{"name": "x", "type": "double"}, {"name": "to", "type": "double"}]}}, None: "double"}}, {"value": {"table": []}, "domain": lambda x, table: True, "type": {"x": {"type": "array", "items": "double"}, "table": {"type": "array", "items": {"type": "record", "name": "Record", "fields": [{"name": "x", "type": {"type": "array", "items": "double"}}, {"name": "to", "type": "double"}]}}, None: "double"}}, {"value": {"table": []}, "domain": lambda x, table, metric: True, "type": {"x": "string", "table": {"type": "array", "items": {"type": "record", "name": "Record", "fields": [{"name": "x", "type": "string"}, {"name": "to", "type": "string"}]}}, "metric": {"params": ["string", "string"], "ret": "double"}, None: "string"}}],
    # interp.nearest: Raises an "inconsistent dimensionality" error if any input <p>x</p> and record <pf>x</pf> have different numbers of dimensions.
    22011: [{"value": {"x": [1, 2, 3], "table": [{"x": [1, 2, 3], "to": 3.14}, {"x": [1, 2], "to": 3.14}]}, "domain": lambda x, table: True, "type": {"x": {"type": "array", "items": "double"}, "table": {"type": "array", "items": {"type": "record", "name": "Record", "fields": [{"name": "x", "type": {"type": "array", "items": "double"}}, {"name": "to", "type": "double"}]}}, None: "double"}}, {"value": {"x": [1, 2, 3], "table": [{"x": [1, 2], "to": 3.14}, {"x": [3, 4], "to": 3.14}]}, "domain": lambda x, table: True, "type": {"x": {"type": "array", "items": "double"}, "table": {"type": "array", "items": {"type": "record", "name": "Record", "fields": [{"name": "x", "type": {"type": "array", "items": "double"}}, {"name": "to", "type": "double"}]}}, None: "double"}}],
    # interp.linear: Raises a "table must have at least two distinct x values" error if fewer than two of the <p>table</p> <pf>x</pf> entries are unique.
    22020: [{"value": {"table": [{"x": 1, "to": 3.14}]}, "domain": lambda x, table: True, "type": {"x": "double", "table": {"type": "array", "items": {"type": "record", "name": "Record", "fields": [{"name": "x", "type": "double"}, {"name": "to", "type": "double"}]}}, None: "double"}}, {"value": {"table": [{"x": 1, "to": 3.14}, {"x": 1, "to": 3.14}]}, "domain": lambda x, table: True, "type": {"x": "double", "table": {"type": "array", "items": {"type": "record", "name": "Record", "fields": [{"name": "x", "type": "double"}, {"name": "to", "type": "double"}]}}, None: "double"}}],
    # interp.linear: Raises an "inconsistent dimensionality" error if the <pf>to</pf> values of the two closest entries have different numbers of dimensions.
    22021: [{"value": {"x": 1, "table": [{"x": 1, "to": [1, 2, 3]}, {"x": 2, "to": [1, 2]}]}, "domain": lambda x, table: True, "type": {"x": "double", "table": {"type": "array", "items": {"type": "record", "name": "Record", "fields": [{"name": "x", "type": "double"}, {"name": "to", "type": {"type": "array", "items": "double"}}]}}, None: {"type": "array", "items": "double"}}}],
    # interp.linearFlat: Raises a "table must have at least two distinct x values" error if <p>table</p> has fewer than two entries.
    22030: [{"value": {"table": [{"x": 1, "to": 3.14}]}, "domain": lambda x, table: True, "type": {"x": "double", "table": {"type": "array", "items": {"type": "record", "name": "Record", "fields": [{"name": "x", "type": "double"}, {"name": "to", "type": "double"}]}}, None: "double"}}, {"value": {"table": [{"x": 1, "to": 3.14}, {"x": 1, "to": 3.14}]}, "domain": lambda x, table: True, "type": {"x": "double", "table": {"type": "array", "items": {"type": "record", "name": "Record", "fields": [{"name": "x", "type": "double"}, {"name": "to", "type": "double"}]}}, None: "double"}}],
    # interp.linearFlat: Raises an "inconsistent dimensionality" error if the <pf>to</pf> values of the two closest entries have different numbers of dimensions.
    22031: [{"value": {"x": 1, "table": [{"x": 1, "to": [1, 2, 3]}, {"x": 2, "to": [1, 2]}]}, "domain": lambda x, table: True, "type": {"x": "double", "table": {"type": "array", "items": {"type": "record", "name": "Record", "fields": [{"name": "x", "type": "double"}, {"name": "to", "type": {"type": "array", "items": "double"}}]}}, None: {"type": "array", "items": "double"}}}],
    # interp.linearMissing: Raises a "table must have at least two distinct x values" error if <p>table</p> has fewer than two entries.
    22040: [{"value": {"table": [{"x": 1, "to": 3.14}]}, "domain": lambda x, table: True, "type": {"x": "double", "table": {"type": "array", "items": {"type": "record", "name": "Record", "fields": [{"name": "x", "type": "double"}, {"name": "to", "type": "double"}]}}, None: ["null", "double"]}}, {"value": {"table": [{"x": 1, "to": 3.14}, {"x": 1, "to": 3.14}]}, "domain": lambda x, table: True, "type": {"x": "double", "table": {"type": "array", "items": {"type": "record", "name": "Record", "fields": [{"name": "x", "type": "double"}, {"name": "to", "type": "double"}]}}, None: ["null", "double"]}}],
    # interp.linearMissing: Raises an "inconsistent dimensionality" error if the <pf>to</pf> values of the two closest entries have different numbers of dimensions.
    22041: [{"value": {"x": 1, "table": [{"x": 1, "to": [1, 2, 3]}, {"x": 2, "to": [1, 2]}]}, "domain": lambda x, table: True, "type": {"x": "double", "table": {"type": "array", "items": {"type": "record", "name": "Record", "fields": [{"name": "x", "type": "double"}, {"name": "to", "type": {"type": "array", "items": "double"}}]}}, None: ["null", {"type": "array", "items": "double"}]}}],
    # prob.dist.gaussianLL: Raises an "invalid parameterization" error if <p>sigma</p> or <pf>variance</pf> is negative.
    13000: [{"value": {"sigma": -0.0001}, "domain": lambda x, mu, sigma: True, "type": {"x": "double", "mu": "double", "sigma": "double", None: "double"}}, {"value": {"params": {"mean": 3.14, "variance": -0.0001}}, "domain": lambda x, params: True, "type": {"x": "double", "params": {"type": "record", "name": "Record", "fields": [{"name": "mean", "type": "double"}, {"name": "variance", "type": "double"}]}, None: "double"}}],
    # prob.dist.gaussianCDF: Raises an "invalid parameterization" error if <p>sigma</p> or <pf>variance</pf> is negative.
    13010: [{"value": {"sigma": -0.0001}, "domain": lambda x, mu, sigma: True, "type": {"x": "double", "mu": "double", "sigma": "double", None: "double"}}, {"value": {"params": {"mean": 3.14, "variance": -0.0001}}, "domain": lambda x, params: True, "type": {"x": "double", "params": {"type": "record", "name": "Record", "fields": [{"name": "mean", "type": "double"}, {"name": "variance", "type": "double"}]}, None: "double"}}],
    # prob.dist.gaussianQF: Raises an "invalid parameterization" error if <p>sigma</p> or <pf>variance</pf> is negative.
    13020: [{"value": {"sigma": -0.0001}, "domain": lambda p, mu, sigma: True, "type": {"p": "double", "mu": "double", "sigma": "double", None: "double"}}, {"value": {"params": {"mean": 3.14, "variance": -0.0001}}, "domain": lambda p, params: True, "type": {"p": "double", "params": {"type": "record", "name": "Record", "fields": [{"name": "mean", "type": "double"}, {"name": "variance", "type": "double"}]}, None: "double"}}],
    # prob.dist.gaussianQF: Raises an "invalid input" error if <p>p</p> is less than zero or greater than one.
    13021: [{"value": {"p": -0.0001}, "domain": lambda p, mu, sigma: True, "type": {"p": "double", "mu": "double", "sigma": "double", None: "double"}}, {"value": {"p": -0.0001}, "domain": lambda p, params: True, "type": {"p": "double", "params": {"type": "record", "name": "Record", "fields": [{"name": "mean", "type": "double"}, {"name": "variance", "type": "double"}]}, None: "double"}}, {"value": {"p": 1.0001}, "domain": lambda p, mu, sigma: True, "type": {"p": "double", "mu": "double", "sigma": "double", None: "double"}}, {"value": {"p": 1.0001}, "domain": lambda p, params: True, "type": {"p": "double", "params": {"type": "record", "name": "Record", "fields": [{"name": "mean", "type": "double"}, {"name": "variance", "type": "double"}]}, None: "double"}}],
    # prob.dist.exponentialPDF: Raises "invalid parameterization" if <m>lambda < 0</m>.
    13030: [{"value": {"lambda": -0.0001}, "domain": lambda x, lamb: True, "type": {"x": "double", "lambda": "double", None: "double"}}],
    # prob.dist.exponentialCDF: Raises "invalid parameterization" if <m>lambda < 0</m>.
    13040: [{"value": {"lambda": -0.0001}, "domain": lambda x, lamb: True, "type": {"x": "double", "lambda": "double", None: "double"}}],
    # prob.dist.exponentialQF: Raises "invalid parameterization" if <m>lambda < 0</m>.
    13050: [{"value": {"lambda": -0.0001}, "domain": lambda p, lamb: True, "type": {"p": "double", "lambda": "double", None: "double"}}],
    # prob.dist.exponentialQF: Raises an "invalid input" error if <p>p</p> is less than zero or greater than one.
    13051: [{"value": {"p": -0.0001}, "domain": lambda p, lamb: True, "type": {"p": "double", "lambda": "double", None: "double"}}, {"value": {"p": 1.0001}, "domain": lambda p, lamb: True, "type": {"p": "double", "lambda": "double", None: "double"}}],
    # prob.dist.chi2PDF: Raises "invalid parameterization" if <p>dof</p> < 0.
    13060: [{"value": {"dof": -1}, "domain": lambda x, dof: True, "type": {"x": "double", "dof": "int", None: "double"}}],
    # prob.dist.chi2CDF: Raises "invalid parameterization" if <p>dof</p> < 0.
    13070: [{"value": {"dof": -1}, "domain": lambda x, dof: True, "type": {"x": "double", "dof": "int", None: "double"}}],
    # prob.dist.chi2QF: Raises "invalid parameterization" if <p>dof</p> < 0.
    13080: [{"value": {"dof": -1}, "domain": lambda p, dof: True, "type": {"p": "double", "dof": "int", None: "double"}}],
    # prob.dist.chi2QF: Raises "invalid input" if <m>p < 0</m> OR if <m>p > 1</m>.
    13081: [{"value": {"p": -0.0001}, "domain": lambda p, dof: True, "type": {"p": "double", "dof": "int", None: "double"}}, {"value": {"p": 1.0001}, "domain": lambda p, dof: True, "type": {"p": "double", "dof": "int", None: "double"}}],
    # prob.dist.poissonPDF: Raises "invalid parameterization" if <m>lambda < 0</m>.
    13090: [{"value": {"lambda": -0.0001}, "domain": lambda x, lamb: True, "type": {"x": "int", "lambda": "double", None: "double"}}],
    # prob.dist.poissonCDF: Raises "invalid parameterization" if <m>lambda < 0</m>.
    13100: [{"value": {"lambda": -0.0001}, "domain": lambda x, lamb: True, "type": {"x": "int", "lambda": "double", None: "double"}}],
    # prob.dist.poissonQF: Raises "invalid parameterization" if <m>lambda < 0</m>.
    13110: [{"value": {"lambda": -0.0001}, "domain": lambda p, lamb: True, "type": {"p": "double", "lambda": "double", None: "double"}}],
    # prob.dist.poissonQF: Raises "invalid input" if <m>p < 0</m> OR if <m>p > 1</m>.
    13111: [{"value": {"p": -0.0001}, "domain": lambda p, lamb: True, "type": {"p": "double", "lambda": "double", None: "double"}}, {"value": {"p": 1.0001}, "domain": lambda p, lamb: True, "type": {"p": "double", "lambda": "double", None: "double"}}],
    # prob.dist.gammaPDF: Raises "invalid parameterization" if the <m>shape < 0</m> OR if <m>scale < 0</m>.
    13120: [{"value": {"shape": -0.0001}, "domain": lambda x, shape, scale: True, "type": {"x": "double", "shape": "double", "scale": "double", None: "double"}}, {"value": {"scale": -0.0001}, "domain": lambda x, shape, scale: True, "type": {"x": "double", "shape": "double", "scale": "double", None: "double"}}],
    # prob.dist.gammaCDF: Raises "invalid parameterization" if the <m>shape < 0</m> OR if <m>scale < 0</m>.
    13130: [{"value": {"shape": -0.0001}, "domain": lambda x, shape, scale: True, "type": {"x": "double", "shape": "double", "scale": "double", None: "double"}}, {"value": {"scale": -0.0001}, "domain": lambda x, shape, scale: True, "type": {"x": "double", "shape": "double", "scale": "double", None: "double"}}],
    # prob.dist.gammaQF: Raises "invalid parameterization" if the <m>shape < 0</m> OR if <m>scale < 0</m>.
    13140: [{"value": {"shape": -0.0001}, "domain": lambda p, shape, scale: True, "type": {"p": "double", "shape": "double", "scale": "double", None: "double"}}, {"value": {"scale": -0.0001}, "domain": lambda p, shape, scale: True, "type": {"p": "double", "shape": "double", "scale": "double", None: "double"}}],
    # prob.dist.gammaQF: Raises "invalid input" if <m>p < 0</m> OR if <m>p > 1</m>.
    13141: [{"value": {"p": -0.0001}, "domain": lambda p, shape, scale: True, "type": {"p": "double", "shape": "double", "scale": "double", None: "double"}}, {"value": {"p": 1.0001}, "domain": lambda p, shape, scale: True, "type": {"p": "double", "shape": "double", "scale": "double", None: "double"}}],
    # prob.dist.betaPDF: Raises "invalid parameterization" if <m>a \leq 0</m> OR if <m>b \leq 0</m>.
    13150: [{"value": {"a": 0}, "domain": lambda x, a, b: True, "type": {"x": "double", "a": "double", "b": "double", None: "double"}}, {"value": {"a": -0.0001}, "domain": lambda x, a, b: True, "type": {"x": "double", "a": "double", "b": "double", None: "double"}}],
    # prob.dist.betaCDF: Raises "invalid parameterization" if <m>a \leq 0</m> OR if <m>b \leq 0</m>.
    13160: [{"value": {"a": 0}, "domain": lambda x, a, b: True, "type": {"x": "double", "a": "double", "b": "double", None: "double"}}, {"value": {"a": -0.0001}, "domain": lambda x, a, b: True, "type": {"x": "double", "a": "double", "b": "double", None: "double"}}],
    # prob.dist.betaQF: Raises "invalid parameterization" if the <m>a \leq 0</m> OR if <m>b \leq 0</m>.
    13170: [{"value": {"a": 0}, "domain": lambda p, a, b: True, "type": {"p": "double", "a": "double", "b": "double", None: "double"}}, {"value": {"a": -0.0001}, "domain": lambda p, a, b: True, "type": {"p": "double", "a": "double", "b": "double", None: "double"}}],
    # prob.dist.betaQF: Raises "invalid input" if <m>p < 0</m> OR if <m>p > 1</m>.
    13171: [{"value": {"p": -0.0001}, "domain": lambda p, a, b: True, "type": {"p": "double", "a": "double", "b": "double", None: "double"}}, {"value": {"p": 1.0001}, "domain": lambda p, a, b: True, "type": {"p": "double", "a": "double", "b": "double", None: "double"}}],
    # prob.dist.cauchyPDF: Raises "invalid parameterization" if <m>scale \leq 0</m>.
    13180: [{"value": {"scale": 0}, "domain": lambda x, location, scale: True, "type": {"x": "double", "location": "double", "scale": "double", None: "double"}}, {"value": {"scale": -0.0001}, "domain": lambda x, location, scale: True, "type": {"x": "double", "location": "double", "scale": "double", None: "double"}}],
    # prob.dist.cauchyCDF: Raises "invalid parameterization" if <m>scale \leq 0</m>.
    13190: [{"value": {"scale": 0}, "domain": lambda x, location, scale: True, "type": {"x": "double", "location": "double", "scale": "double", None: "double"}}, {"value": {"scale": -0.0001}, "domain": lambda x, location, scale: True, "type": {"x": "double", "location": "double", "scale": "double", None: "double"}}],
    # prob.dist.cauchyQF: Raises "invalid parameterization" if <m>scale \leq 0</m>.
    13200: [{"value": {"scale": 0}, "domain": lambda p, location, scale: True, "type": {"p": "double", "location": "double", "scale": "double", None: "double"}}, {"value": {"scale": -0.0001}, "domain": lambda p, location, scale: True, "type": {"p": "double", "location": "double", "scale": "double", None: "double"}}],
    # prob.dist.cauchyQF: Raises "invalid input" if <m>p < 0</m> OR if <m>p > 1</m>.
    13201: [{"value": {"p": -0.0001}, "domain": lambda p, location, scale: True, "type": {"p": "double", "location": "double", "scale": "double", None: "double"}}, {"value": {"p": 1.0001}, "domain": lambda p, location, scale: True, "type": {"p": "double", "location": "double", "scale": "double", None: "double"}}],
    # prob.dist.fPDF: Raises "invalid parameterization" if the <m>d1 \leq 0</m> OR if <m>d2 \leq 0</m>.
    13210: [{"value": {"d1": 0}, "domain": lambda x, d1, d2: True, "type": {"x": "double", "d1": "int", "d2": "int", None: "double"}}, {"value": {"d1": -1}, "domain": lambda x, d1, d2: True, "type": {"x": "double", "d1": "int", "d2": "int", None: "double"}}, {"value": {"d2": 0}, "domain": lambda x, d1, d2: True, "type": {"x": "double", "d1": "int", "d2": "int", None: "double"}}, {"value": {"d2": -1}, "domain": lambda x, d1, d2: True, "type": {"x": "double", "d1": "int", "d2": "int", None: "double"}}],
    # prob.dist.fCDF: Raises "invalid parameterization" if the <m>d1 \leq 0</m> OR if <m>d2 \leq 0</m>.
    13220: [{"value": {"d1": 0}, "domain": lambda x, d1, d2: True, "type": {"x": "double", "d1": "int", "d2": "int", None: "double"}}, {"value": {"d1": -1}, "domain": lambda x, d1, d2: True, "type": {"x": "double", "d1": "int", "d2": "int", None: "double"}}, {"value": {"d2": 0}, "domain": lambda x, d1, d2: True, "type": {"x": "double", "d1": "int", "d2": "int", None: "double"}}, {"value": {"d2": -1}, "domain": lambda x, d1, d2: True, "type": {"x": "double", "d1": "int", "d2": "int", None: "double"}}],
    # prob.dist.fQF: Raises "invalid parameterization" if the <m>d1 \leq 0</m> OR if <m>d2 \leq 0</m>.
    13230: [{"value": {"d1": 0}, "domain": lambda p, d1, d2: True, "type": {"p": "double", "d1": "int", "d2": "int", None: "double"}}, {"value": {"d1": -1}, "domain": lambda p, d1, d2: True, "type": {"p": "double", "d1": "int", "d2": "int", None: "double"}}, {"value": {"d2": 0}, "domain": lambda p, d1, d2: True, "type": {"p": "double", "d1": "int", "d2": "int", None: "double"}}, {"value": {"d2": -1}, "domain": lambda p, d1, d2: True, "type": {"p": "double", "d1": "int", "d2": "int", None: "double"}}],
    # prob.dist.fQF: Raises "invalid input" if <m>p < 0</m> OR if <m>p > 1</m>.
    13231: [{"value": {"p": -0.0001}, "domain": lambda p, d1, d2: True, "type": {"p": "double", "d1": "int", "d2": "int", None: "double"}}, {"value": {"p": 1.0001}, "domain": lambda p, d1, d2: True, "type": {"p": "double", "d1": "int", "d2": "int", None: "double"}}],
    # prob.dist.lognormalPDF: Raises "invalid parameterization" if <m>sdlog \leq 0</m>.
    13240: [{"value": {"sdlog": 0}, "domain": lambda x, meanlog, sdlog: True, "type": {"x": "double", "meanlog": "double", "sdlog": "double", None: "double"}}, {"value": {"sdlog": -0.0001}, "domain": lambda x, meanlog, sdlog: True, "type": {"x": "double", "meanlog": "double", "sdlog": "double", None: "double"}}],
    # prob.dist.lognormalCDF: Raises "invalid parameterization" if <m>sdlog \leq 0</m>.
    13250: [{"value": {"sdlog": 0}, "domain": lambda x, meanlog, sdlog: True, "type": {"x": "double", "meanlog": "double", "sdlog": "double", None: "double"}}, {"value": {"sdlog": -0.0001}, "domain": lambda x, meanlog, sdlog: True, "type": {"x": "double", "meanlog": "double", "sdlog": "double", None: "double"}}],
    # prob.dist.lognormalQF: Raises "invalid parameterization" if <m>sdlog \leq 0</m>.
    13260: [{"value": {"sdlog": 0}, "domain": lambda p, meanlog, sdlog: True, "type": {"p": "double", "meanlog": "double", "sdlog": "double", None: "double"}}, {"value": {"sdlog": -0.0001}, "domain": lambda p, meanlog, sdlog: True, "type": {"p": "double", "meanlog": "double", "sdlog": "double", None: "double"}}],
    # prob.dist.lognormalQF: Raises "invalid input" if <m>p < 0</m> OR if <m>p > 1</m>.
    13261: [{"value": {"p": -0.0001}, "domain": lambda p, meanlog, sdlog: True, "type": {"p": "double", "meanlog": "double", "sdlog": "double", None: "double"}}, {"value": {"p": 1.0001}, "domain": lambda p, meanlog, sdlog: True, "type": {"p": "double", "meanlog": "double", "sdlog": "double", None: "double"}}],
    # prob.dist.tPDF: Raises "invalid parameterization" if <m>df \leq 0</m>.
    13270: [{"value": {"dof": 0}, "domain": lambda x, dof: True, "type": {"x": "double", "dof": "int", None: "double"}}, {"value": {"dof": -1}, "domain": lambda x, dof: True, "type": {"x": "double", "dof": "int", None: "double"}}],
    # prob.dist.tCDF: Raises "invalid parameterization" if <m>df \leq 0</m>.
    13280: [{"value": {"dof": 0}, "domain": lambda x, dof: True, "type": {"x": "double", "dof": "int", None: "double"}}, {"value": {"dof": -1}, "domain": lambda x, dof: True, "type": {"x": "double", "dof": "int", None: "double"}}],
    # prob.dist.tQF: Raises "invalid parameterization" if <m>df \leq 0</m>.
    13290: [{"value": {"dof": 0}, "domain": lambda p, dof: True, "type": {"p": "double", "dof": "int", None: "double"}}, {"value": {"dof": -1}, "domain": lambda p, dof: True, "type": {"p": "double", "dof": "int", None: "double"}}],
    # prob.dist.tQF: Raises "invalid input" if <m>p < 0</m> OR if <m>p > 1</m>.
    13291: [{"value": {"p": -0.0001}, "domain": lambda p, dof: True, "type": {"p": "double", "dof": "int", None: "double"}}, {"value": {"p": 1.0001}, "domain": lambda p, dof: True, "type": {"p": "double", "dof": "int", None: "double"}}],
    # prob.dist.binomialPDF: Raises "invalid parameterization" if <m>size < 0</m> OR if <m>prob < 0</m> OR if <m>prob > 1</m>.
    13300: [{"value": {"size": -1}, "domain": lambda x, size, prob: True, "type": {"x": "int", "size": "int", "prob": "double", None: "double"}}, {"value": {"prob": -0.0001}, "domain": lambda x, size, prob: True, "type": {"x": "int", "size": "int", "prob": "double", None: "double"}}, {"value": {"prob": 1.0001}, "domain": lambda x, size, prob: True, "type": {"x": "int", "size": "int", "prob": "double", None: "double"}}],
    # prob.dist.binomialCDF: Raises "invalid parameterization" if <m>size < 0</m> OR if <m>prob < 0</m> OR if <m>prob > 1</m>.
    13310: [{"value": {"size": -1}, "domain": lambda x, size, prob: True, "type": {"x": "double", "size": "int", "prob": "double", None: "double"}}, {"value": {"prob": -0.0001}, "domain": lambda x, size, prob: True, "type": {"x": "double", "size": "int", "prob": "double", None: "double"}}, {"value": {"prob": 1.0001}, "domain": lambda x, size, prob: True, "type": {"x": "double", "size": "int", "prob": "double", None: "double"}}],
    # prob.dist.binomialQF: Raises "invalid parameterization" if <m>size < 0</m> OR if <m>prob < 0</m> OR if <m>prob > 1</m>.
    13320: [{"value": {"size": -1}, "domain": lambda p, size, prob: True, "type": {"p": "double", "size": "int", "prob": "double", None: "double"}}, {"value": {"prob": -0.0001}, "domain": lambda p, size, prob: True, "type": {"p": "double", "size": "int", "prob": "double", None: "double"}}, {"value": {"prob": 1.0001}, "domain": lambda p, size, prob: True, "type": {"p": "double", "size": "int", "prob": "double", None: "double"}}],
    # prob.dist.binomialQF: Raises "invalid input" if <m>p < 0</m> OR if <m>p > 1</m>.
    13321: [{"value": {"p": -0.0001}, "domain": lambda p, size, prob: True, "type": {"p": "double", "size": "int", "prob": "double", None: "double"}}, {"value": {"p": 1.0001}, "domain": lambda p, size, prob: True, "type": {"p": "double", "size": "int", "prob": "double", None: "double"}}],
    # prob.dist.uniformPDF: Raises "invalid parameterization" if <m>min \geq max</m>.
    13330: [{"value": {"min": 3.14, "max": 3.14}, "domain": lambda x, min, max: True, "type": {"x": "double", "min": "double", "max": "double", None: "double"}}, {"value": {"min": 3.14, "max": 2.2}, "domain": lambda x, min, max: True, "type": {"x": "double", "min": "double", "max": "double", None: "double"}}],
    # prob.dist.uniformCDF: Raises "invalid parameterization" if <m>min \geq max</m>.
    13340: [{"value": {"min": 3.14, "max": 3.14}, "domain": lambda x, min, max: True, "type": {"x": "double", "min": "double", "max": "double", None: "double"}}, {"value": {"min": 3.14, "max": 2.2}, "domain": lambda x, min, max: True, "type": {"x": "double", "min": "double", "max": "double", None: "double"}}],
    # prob.dist.uniformQF: Raises "invalid parameterization" if <m>min \geq max</m>.
    13350: [{"value": {"min": 3.14, "max": 3.14}, "domain": lambda p, min, max: True, "type": {"p": "double", "min": "double", "max": "double", None: "double"}}, {"value": {"min": 3.14, "max": 2.2}, "domain": lambda p, min, max: True, "type": {"p": "double", "min": "double", "max": "double", None: "double"}}],
    # prob.dist.uniformQF: Raises "invalid input" if <m>p < 0</m> OR if <m>p > 1</m>.
    13351: [{"value": {"p": -0.0001}, "domain": lambda p, min, max: True, "type": {"p": "double", "min": "double", "max": "double", None: "double"}}, {"value": {"p": 1.0001}, "domain": lambda p, min, max: True, "type": {"p": "double", "min": "double", "max": "double", None: "double"}}],
    # prob.dist.geometricPDF: Raises "invalid parameterization" if <m>\mathrm{prob} \leq 0</m> OR if <m>\mathrm{prob} > 1</m>.
    13360: [{"value": {"prob": 0}, "domain": lambda x, prob: True, "type": {"x": "int", "prob": "double", None: "double"}}, {"value": {"prob": -0.0001}, "domain": lambda x, prob: True, "type": {"x": "int", "prob": "double", None: "double"}}, {"value": {"prob": 1.0001}, "domain": lambda x, prob: True, "type": {"x": "int", "prob": "double", None: "double"}}],
    # prob.dist.geometricCDF: Raises "invalid parameterization" if <m>\mathrm{prob} \leq 0</m> OR if <m>\mathrm{prob} > 1</m>.
    13370: [{"value": {"prob": 0}, "domain": lambda x, prob: True, "type": {"x": "double", "prob": "double", None: "double"}}, {"value": {"prob": -0.0001}, "domain": lambda x, prob: True, "type": {"x": "double", "prob": "double", None: "double"}}, {"value": {"prob": 1.0001}, "domain": lambda x, prob: True, "type": {"x": "double", "prob": "double", None: "double"}}],
    # prob.dist.geometricQF: Raises "invalid parameterization" if <m>\mathrm{prob} \leq 0</m> OR if <m>\mathrm{prob} > 1</m>.
    13380: [{"value": {"prob": 0}, "domain": lambda p, prob: True, "type": {"p": "double", "prob": "double", None: "double"}}, {"value": {"prob": -0.0001}, "domain": lambda p, prob: True, "type": {"p": "double", "prob": "double", None: "double"}}, {"value": {"prob": 1.0001}, "domain": lambda p, prob: True, "type": {"p": "double", "prob": "double", None: "double"}}],
    # prob.dist.geometricQF: Raises "invalid input" if <m>p < 0</m> OR if <m>p > 1</m>.
    13381: [{"value": {"p": -0.0001}, "domain": lambda p, prob: True, "type": {"p": "double", "prob": "double", None: "double"}}, {"value": {"p": 1.0001}, "domain": lambda p, prob: True, "type": {"p": "double", "prob": "double", None: "double"}}],
    # prob.dist.hypergeometricPDF: Raises "invalid parameterization" if the <m>\mathrm{m} + \mathrm{n} > \mathrm{k}</m>.
    13390: [{"value": {"m": 3, "n": 4, "k": 8}, "domain": lambda x, m, n, k: True, "type": {"x": "int", "m": "int", "n": "int", "k": "int", None: "double"}}],
    # prob.dist.hypergeometricCDF: Raises "invalid parameterization" if the <m>\mathrm{m} + \mathrm{n} > \mathrm{k}</m>.
    13400: [{"value": {"m": 3, "n": 4, "k": 8}, "domain": lambda x, m, n, k: True, "type": {"x": "int", "m": "int", "n": "int", "k": "int", None: "double"}}],
    # prob.dist.hypergeometricQF: Raises "invalid parameterization" if the <m>\mathrm{m} + \mathrm{n} > \mathrm{k}</m>.
    13410: [{"value": {"m": 3, "n": 4, "k": 8}, "domain": lambda p, m, n, k: True, "type": {"p": "double", "m": "int", "n": "int", "k": "int", None: "double"}}],
    # prob.dist.hypergeometricQF: Raises "invalid input" if <m>p < 0</m> OR if <m>p > 1</m>.
    13411: [{"value": {"p": -0.0001}, "domain": lambda p, m, n, k: True, "type": {"p": "double", "m": "int", "n": "int", "k": "int", None: "double"}}, {"value": {"p": 1.0001}, "domain": lambda p, m, n, k: True, "type": {"p": "double", "m": "int", "n": "int", "k": "int", None: "double"}}],
    # prob.dist.weibullPDF: Raises "invalid parameterization" if the <m>shape \leq 0</m> OR if <m>scale \leq 0</m>.
    13420: [{"value": {"shape": 0}, "domain": lambda x, shape, scale: True, "type": {"x": "double", "shape": "double", "scale": "double", None: "double"}}, {"value": {"shape": -0.0001}, "domain": lambda x, shape, scale: True, "type": {"x": "double", "shape": "double", "scale": "double", None: "double"}}, {"value": {"scale": 0}, "domain": lambda x, shape, scale: True, "type": {"x": "double", "shape": "double", "scale": "double", None: "double"}}, {"value": {"scale": -0.0001}, "domain": lambda x, shape, scale: True, "type": {"x": "double", "shape": "double", "scale": "double", None: "double"}}],
    # prob.dist.weibullCDF: Raises "invalid parameterization" if the <m>shape \leq 0</m> OR if <m>scale \leq 0</m>.
    13430: [{"value": {"shape": 0}, "domain": lambda x, shape, scale: True, "type": {"x": "double", "shape": "double", "scale": "double", None: "double"}}, {"value": {"shape": -0.0001}, "domain": lambda x, shape, scale: True, "type": {"x": "double", "shape": "double", "scale": "double", None: "double"}}, {"value": {"scale": 0}, "domain": lambda x, shape, scale: True, "type": {"x": "double", "shape": "double", "scale": "double", None: "double"}}, {"value": {"scale": -0.0001}, "domain": lambda x, shape, scale: True, "type": {"x": "double", "shape": "double", "scale": "double", None: "double"}}],
    # prob.dist.weibullQF: Raises "invalid parameterization" if the <m>shape \leq 0</m> OR if <m>scale \leq 0</m>.
    13440: [{"value": {"shape": 0}, "domain": lambda p, shape, scale: True, "type": {"p": "double", "shape": "double", "scale": "double", None: "double"}}, {"value": {"shape": -0.0001}, "domain": lambda p, shape, scale: True, "type": {"p": "double", "shape": "double", "scale": "double", None: "double"}}, {"value": {"scale": 0}, "domain": lambda p, shape, scale: True, "type": {"p": "double", "shape": "double", "scale": "double", None: "double"}}, {"value": {"scale": -0.0001}, "domain": lambda p, shape, scale: True, "type": {"p": "double", "shape": "double", "scale": "double", None: "double"}}],
    # prob.dist.weibullQF: Raises "invalid input" if <m>p < 0</m> OR if <m>p > 1</m>.
    13441: [{"value": {"p": -0.0001}, "domain": lambda p, shape, scale: True, "type": {"p": "double", "shape": "double", "scale": "double", None: "double"}}, {"value": {"p": 1.0001}, "domain": lambda p, shape, scale: True, "type": {"p": "double", "shape": "double", "scale": "double", None: "double"}}],
    # prob.dist.negativeBinomialPDF: Raises "invalid parameterization" if <m>\mathrm{prob} < 0</m>, if <m>\mathrm{prob} > 1</m> or if <m>size < 0</m>.
    13450: [{"value": {"size": -1}, "domain": lambda x, size, prob: True, "type": {"x": "int", "size": "int", "prob": "double", None: "double"}}, {"value": {"prob": -0.0001}, "domain": lambda x, size, prob: True, "type": {"x": "int", "size": "int", "prob": "double", None: "double"}}, {"value": {"prob": 1.0001}, "domain": lambda x, size, prob: True, "type": {"x": "int", "size": "int", "prob": "double", None: "double"}}],
    # prob.dist.negativeBinomialCDF: Raises "invalid parameterization" if <m>\mathrm{prob} < 0</m>, if <m>\mathrm{prob} > 1</m>, or if <m>size < 0</m>.
    13460: [{"value": {"size": -1}, "domain": lambda x, size, prob: True, "type": {"x": "double", "size": "int", "prob": "double", None: "double"}}, {"value": {"prob": -0.0001}, "domain": lambda x, size, prob: True, "type": {"x": "double", "size": "int", "prob": "double", None: "double"}}, {"value": {"prob": 1.0001}, "domain": lambda x, size, prob: True, "type": {"x": "double", "size": "int", "prob": "double", None: "double"}}],
    # prob.dist.negativeBinomialQF: Raises "invalid parameterization" if <m>\mathrm{prob} < 0</m>, if <m>\mathrm{prob} > 1</m>, or if <m>size \leq 0</m>, or if <m>size</m>.
    13470: [{"value": {"size": -1}, "domain": lambda p, size, prob: True, "type": {"p": "double", "size": "int", "prob": "double", None: "double"}}, {"value": {"prob": -0.0001}, "domain": lambda p, size, prob: True, "type": {"p": "double", "size": "int", "prob": "double", None: "double"}}, {"value": {"prob": 1.0001}, "domain": lambda p, size, prob: True, "type": {"p": "double", "size": "int", "prob": "double", None: "double"}}],
    # prob.dist.negativeBinomialQF: Raises "invalid input" if <m>p < 0</m> OR if <m>p > 1</m>.
    13471: [{"value": {"p": -0.0001}, "domain": lambda p, size, prob: True, "type": {"p": "double", "size": "int", "prob": "double", None: "double"}}, {"value": {"p": 1.0001}, "domain": lambda p, size, prob: True, "type": {"p": "double", "size": "int", "prob": "double", None: "double"}}],
    # stat.test.residual: Raises a "misaligned prediction" error if <p>prediction</p> does not have the same indexes or keys as <p>observation</p>.
    38010: [{"value": {"observation": [1, 2], "prediction": [1, 2, 3]}, "domain": lambda observation, prediciton: True, "type": {"observation": {"type": "array", "items": "double"}, "prediciton": {"type": "array", "items": "double"}, None: {"type": "array", "items": "double"}}}, {"value": {"observation": {"one": 1, "two": 2}, "prediction": {"one": 1, "two": 2, "three": 3}}, "domain": lambda observation, prediciton: True, "type": {"observation": {"type": "map", "values": "double"}, "prediciton": {"type": "map", "values": "double"}, None: {"type": "map", "values": "double"}}}],
    # stat.test.pull: Raises a "misaligned prediction" error if <p>prediction</p> does not have the same indexes or keys as <p>observation</p>.
    38020: [{"value": {"observation": [1, 2], "prediction": [1, 2, 3], "uncertainty": [1, 2, 3]}, "domain": lambda observation, prediciton, uncertainty: True, "type": {"observation": {"type": "array", "items": "double"}, "prediciton": {"type": "array", "items": "double"}, "uncertainty": {"type": "array", "items": "double"}, None: {"type": "array", "items": "double"}}}, {"value": {"observation": {"one": 1, "two": 2}, "prediction": {"one": 1, "two": 2, "three": 3}, "uncertainty": {"one": 1, "two": 2, "three": 3}}, "domain": lambda observation, prediciton, uncertainty: True, "type": {"observation": {"type": "map", "values": "double"}, "prediciton": {"type": "map", "values": "double"}, "uncertainty": {"type": "map", "values": "double"}, None: {"type": "map", "values": "double"}}}],
    # stat.test.pull: Raises a "misaligned uncertainty" error if <p>prediction</p> does not have the same indexes or keys as <p>uncertainty</p>.
    38021: [{"value": {"observation": [1, 2, 3], "prediction": [1, 2, 3], "uncertainty": [1, 2]}, "domain": lambda observation, prediciton, uncertainty: True, "type": {"observation": {"type": "array", "items": "double"}, "prediciton": {"type": "array", "items": "double"}, "uncertainty": {"type": "array", "items": "double"}, None: {"type": "array", "items": "double"}}}, {"value": {"observation": {"one": 1, "two": 2, "three": 3}, "prediction": {"one": 1, "two": 2, "three": 3}, "uncertainty": {"one": 1, "two": 2}}, "domain": lambda observation, prediciton, uncertainty: True, "type": {"observation": {"type": "map", "values": "double"}, "prediciton": {"type": "map", "values": "double"}, "uncertainty": {"type": "map", "values": "double"}, None: {"type": "map", "values": "double"}}}],
    # stat.test.mahalanobis: Raises a "too few rows/cols" error if <p>observation</p> has fewer than one element.
    38030: [{"value": {"observation": [], "prediction": [], "covariance": []}, "domain": lambda observation, prediction, covariance: True, "type": {"observation": {"type": "array", "items": "double"}, "prediction": {"type": "array", "items": "double"}, "covariance": {"type": "array", "items": {"type": "array", "items": "double"}}, None: "double"}}, {"value": {"observation": {}, "prediction": {}, "covariance": {}}, "domain": lambda observation, prediction, covariance: True, "type": {"observation": {"type": "map", "values": "double"}, "prediction": {"type": "map", "values": "double"}, "covariance": {"type": "map", "values": {"type": "map", "values": "double"}}, None: "double"}}],
    # stat.test.mahalanobis: Raises a "misaligned prediction" error if <p>prediction</p> does not have the same indexes or keys as <p>observation</p>.
    38031: [{"value": {"observation": [1, 2], "prediction": [1, 2, 3], "covariance": [[1, 2, 3], [1, 2, 3], [1, 2, 3]]}, "domain": lambda observation, prediction, covariance: True, "type": {"observation": {"type": "array", "items": "double"}, "prediction": {"type": "array", "items": "double"}, "covariance": {"type": "array", "items": {"type": "array", "items": "double"}}, None: "double"}}, {"value": {"observation": {"one": 1, "two": 2}, "prediction": {"one": 1, "two": 2, "three": 3}, "covariance": {"one": {"one": 1, "two": 2, "three": 3}, "two": {"one": 1, "two": 2, "three": 3}, "three": {"one": 1, "two": 2, "three": 3}}}, "domain": lambda observation, prediction, covariance: True, "type": {"observation": {"type": "map", "values": "double"}, "prediction": {"type": "map", "values": "double"}, "covariance": {"type": "map", "values": {"type": "map", "values": "double"}}, None: "double"}}],
    # stat.test.mahalanobis: Raises a "misaligned covariance" error if <p>covariance</p> does not have the same indexes or keys as <p>observation</p>.
    38032: [{"value": {"observation": [1, 2, 3], "prediction": [1, 2, 3], "covariance": [[1, 2], [1, 2]]}, "domain": lambda observation, prediction, covariance: True, "type": {"observation": {"type": "array", "items": "double"}, "prediction": {"type": "array", "items": "double"}, "covariance": {"type": "array", "items": {"type": "array", "items": "double"}}, None: "double"}}, {"value": {"observation": {"one": 1, "two": 2, "three": 3}, "prediction": {"one": 1, "two": 2, "three": 3}, "covariance": {"one": {"one": 1, "two": 2}, "two": {"one": 1, "two": 2}}}, "domain": lambda observation, prediction, covariance: True, "type": {"observation": {"type": "map", "values": "double"}, "prediction": {"type": "map", "values": "double"}, "covariance": {"type": "map", "values": {"type": "map", "values": "double"}}, None: "double"}}],
    # stat.test.chi2Prob: Raises "invalid parameterization" if <pf>dof</pf> is less than zero.
    38060: [{"value": {"state": {"chi2": 3.14, "dof": -1}}, "domain": lambda state: True, "type": {"state": {"type": "record", "name": "Record", "fields": [{"name": "chi2", "type": "double"}, {"name": "dof", "type": "int"}]}, None: "double"}}],
    # stat.sample.updateCovariance: If <p>x</p> has fewer than 2 components, a "too few components" error is raised.
    14011: [{"value": {"x": [1]}, "domain": lambda x, w, state: True, "type": {"x": {"type": "array", "items": "double"}, "w": "double", "state": {"type": "record", "name": "Record", "fields": [{"name": "count", "type": "double"}, {"name": "mean", "type": {"type": "array", "items": "double"}}, {"name": "covariance", "type": {"type": "array", "items": {"type": "array", "items": "double"}}}]}, None: "Record"}}, {"value": {"x": []}, "domain": lambda x, w, state: True, "type": {"x": {"type": "array", "items": "double"}, "w": "double", "state": {"type": "record", "name": "Record", "fields": [{"name": "count", "type": "double"}, {"name": "mean", "type": {"type": "array", "items": "double"}}, {"name": "covariance", "type": {"type": "array", "items": {"type": "array", "items": "double"}}}]}, None: "Record"}}, {"value": {"x": {"one": 1}}, "domain": lambda x, w, state: True, "type": {"x": {"type": "map", "values": "double"}, "w": "double", "state": {"type": "record", "name": "Record", "fields": [{"name": "count", "type": {"type": "map", "values": {"type": "map", "values": "double"}}}, {"name": "mean", "type": {"type": "map", "values": "double"}}, {"name": "covariance", "type": {"type": "map", "values": {"type": "map", "values": "double"}}}]}, None: "Record"}}, {"value": {"x": {}}, "domain": lambda x, w, state: True, "type": {"x": {"type": "map", "values": "double"}, "w": "double", "state": {"type": "record", "name": "Record", "fields": [{"name": "count", "type": {"type": "map", "values": {"type": "map", "values": "double"}}}, {"name": "mean", "type": {"type": "map", "values": "double"}}, {"name": "covariance", "type": {"type": "map", "values": {"type": "map", "values": "double"}}}]}, None: "Record"}}],
    # stat.sample.updateCovariance: If <p>x</p>, <pf>mean</pf>, and <pf>covariance</pf> are arrays with unequal lengths, an "unequal length arrays" error is raised.
    14012: [{"value": {"x": [1, 2], "state": {"count": 1, "mean": [1, 2, 3], "covariance": [[1, 2, 3], [1, 2, 3], [1, 2, 3]]}}, "domain": lambda x, w, state: True, "type": {"x": {"type": "array", "items": "double"}, "w": "double", "state": {"type": "record", "name": "Record", "fields": [{"name": "count", "type": "double"}, {"name": "mean", "type": {"type": "array", "items": "double"}}, {"name": "covariance", "type": {"type": "array", "items": {"type": "array", "items": "double"}}}]}, None: "Record"}}, {"value": {"x": [1, 2, 3], "state": {"count": 1, "mean": [1, 2], "covariance": [[1, 2, 3], [1, 2, 3], [1, 2, 3]]}}, "domain": lambda x, w, state: True, "type": {"x": {"type": "array", "items": "double"}, "w": "double", "state": {"type": "record", "name": "Record", "fields": [{"name": "count", "type": "double"}, {"name": "mean", "type": {"type": "array", "items": "double"}}, {"name": "covariance", "type": {"type": "array", "items": {"type": "array", "items": "double"}}}]}, None: "Record"}}, {"value": {"x": [1, 2, 3], "state": {"count": 1, "mean": [1, 2, 3], "covariance": [[1, 2], [1, 2], [1, 2]]}}, "domain": lambda x, w, state: True, "type": {"x": {"type": "array", "items": "double"}, "w": "double", "state": {"type": "record", "name": "Record", "fields": [{"name": "count", "type": "double"}, {"name": "mean", "type": {"type": "array", "items": "double"}}, {"name": "covariance", "type": {"type": "array", "items": {"type": "array", "items": "double"}}}]}, None: "Record"}}, {"value": {"x": [1, 2, 3], "state": {"count": 1, "mean": [1, 2, 3], "covariance": [[1, 2], [1, 2]]}}, "domain": lambda x, w, state: True, "type": {"x": {"type": "array", "items": "double"}, "w": "double", "state": {"type": "record", "name": "Record", "fields": [{"name": "count", "type": "double"}, {"name": "mean", "type": {"type": "array", "items": "double"}}, {"name": "covariance", "type": {"type": "array", "items": {"type": "array", "items": "double"}}}]}, None: "Record"}}, {"value": {"x": [1, 2, 3], "state": {"count": 1, "mean": [1, 2, 3], "covariance": [[1, 2, 3], [1, 2, 3], [1, 2]]}}, "domain": lambda x, w, state: True, "type": {"x": {"type": "array", "items": "double"}, "w": "double", "state": {"type": "record", "name": "Record", "fields": [{"name": "count", "type": "double"}, {"name": "mean", "type": {"type": "array", "items": "double"}}, {"name": "covariance", "type": {"type": "array", "items": {"type": "array", "items": "double"}}}]}, None: "Record"}}, {"value": {"x": [1, 2, 3], "state": {"count": 1, "mean": [1, 2, 3], "covariance": [[1, 2, 3], [1, 2, 3]]}}, "domain": lambda x, w, state: True, "type": {"x": {"type": "array", "items": "double"}, "w": "double", "state": {"type": "record", "name": "Record", "fields": [{"name": "count", "type": "double"}, {"name": "mean", "type": {"type": "array", "items": "double"}}, {"name": "covariance", "type": {"type": "array", "items": {"type": "array", "items": "double"}}}]}, None: "Record"}}],
    # stat.sample.updateWindow: If <p>windowSize</p> is less than 2, a "windowSize must be at least 2" error is raised.
    14020: [{"value": {"windowSize": 1}, "domain": lambda x, w, state, windowSize: True, "type": {"x": "double", "w": "double", "state": {"type": "array", "items": {"type": "record", "name": "Record", "fields": [{"name": "x", "type": "double"}, {"name": "w", "type": "double"}, {"name": "count", "type": "double"}]}}, "windowSize": "int", None: {"type": "array", "items": "Record"}}}, {"value": {"windowSize": 0}, "domain": lambda x, w, state, windowSize: True, "type": {"x": "double", "w": "double", "state": {"type": "array", "items": {"type": "record", "name": "Record", "fields": [{"name": "x", "type": "double"}, {"name": "w", "type": "double"}, {"name": "count", "type": "double"}]}}, "windowSize": "int", None: {"type": "array", "items": "Record"}}}, {"value": {"windowSize": -1}, "domain": lambda x, w, state, windowSize: True, "type": {"x": "double", "w": "double", "state": {"type": "array", "items": {"type": "record", "name": "Record", "fields": [{"name": "x", "type": "double"}, {"name": "w", "type": "double"}, {"name": "count", "type": "double"}]}}, "windowSize": "int", None: {"type": "array", "items": "Record"}}}],
    # stat.sample.updateWindow: If <p>state</p> is empty and the record type has fields other than <pf>x</pf>, <pf>w</pf>, <pf>count</pf>, <pf>mean</pf>, and <pf>variance</pf>, then a "cannot initialize unrecognized fields" error is raised.  Unrecognized fields are only allowed if an initial record is provided.
    14021: [{"value": {"state": []}, "domain": lambda x, w, state, windowSize: True, "type": {"x": "double", "w": "double", "state": {"type": "array", "items": {"type": "record", "name": "Record", "fields": [{"name": "x", "type": "double"}, {"name": "w", "type": "double"}, {"name": "count", "type": "double"}, {"name": "another", "type": "double"}]}}, "windowSize": "int", None: {"type": "array", "items": "Record"}}}],
    # stat.sample.updateEWMA: If <p>alpha</p> is less than 0 or greater than 1, an "alpha out of range" error is raised.
    14030: [{"value": {"alpha": -0.0001}, "domain": lambda x, alpha, state: True, "type": {"x": "double", "alpha": "double", "state": {"type": "record", "name": "Record", "fields": [{"name": "mean", "type": "double"}]}, None: "Record"}}, {"value": {"alpha": 1.0001}, "domain": lambda x, alpha, state: True, "type": {"x": "double", "alpha": "double", "state": {"type": "record", "name": "Record", "fields": [{"name": "mean", "type": "double"}]}, None: "Record"}}],
    # stat.sample.updateHoltWinters: If <p>alpha</p> is less than 0 or greater than 1, an "alpha out of range" error is raised.
    14040: [{"value": {"alpha": -0.0001}, "domain": lambda x, alpha, beta, state: True, "type": {"x": "double", "alpha": "double", "beta": "double", "state": {"type": "record", "name": "Record", "fields": [{"name": "level", "type": "double"}, {"name": "trend", "type": "double"}]}, None: "Record"}}, {"value": {"alpha": 1.0001}, "domain": lambda x, alpha, beta, state: True, "type": {"x": "double", "alpha": "double", "beta": "double", "state": {"type": "record", "name": "Record", "fields": [{"name": "level", "type": "double"}, {"name": "trend", "type": "double"}]}, None: "Record"}}],
    # stat.sample.updateHoltWinters: If <p>beta</p> is less than 0 or greater than 1, an "beta out of range" error is raised.
    14041: [{"value": {"beta": -0.0001}, "domain": lambda x, alpha, beta, state: True, "type": {"x": "double", "alpha": "double", "beta": "double", "state": {"type": "record", "name": "Record", "fields": [{"name": "level", "type": "double"}, {"name": "trend", "type": "double"}]}, None: "Record"}}, {"value": {"beta": 1.0001}, "domain": lambda x, alpha, beta, state: True, "type": {"x": "double", "alpha": "double", "beta": "double", "state": {"type": "record", "name": "Record", "fields": [{"name": "level", "type": "double"}, {"name": "trend", "type": "double"}]}, None: "Record"}}],
    # stat.sample.updateHoltWintersPeriodic: If <p>alpha</p> is less than 0 or greater than 1, an "alpha out of range" error is raised.
    14050: [{"value": {"alpha": -0.0001}, "domain": lambda x, alpha, beta, gamma, state: True, "type": {"x": "double", "alpha": "double", "beta": "double", "gamma": "double", "state": {"type": "record", "name": "Record", "fields": [{"name": "level", "type": "double"}, {"name": "trend", "type": "double"}, {"name": "cycle", "type": {"type": "array", "items": "double"}}, {"name": "multiplicative", "type": "boolean"}]}, None: "Record"}}, {"value": {"alpha": 1.0001}, "domain": lambda x, alpha, beta, gamma, state: True, "type": {"x": "double", "alpha": "double", "beta": "double", "gamma": "double", "state": {"type": "record", "name": "Record", "fields": [{"name": "level", "type": "double"}, {"name": "trend", "type": "double"}, {"name": "cycle", "type": {"type": "array", "items": "double"}}, {"name": "multiplicative", "type": "boolean"}]}, None: "Record"}}],
    # stat.sample.updateHoltWintersPeriodic: If <p>beta</p> is less than 0 or greater than 1, an "beta out of range" error is raised.
    14051: [{"value": {"beta": -0.0001}, "domain": lambda x, alpha, beta, gamma, state: True, "type": {"x": "double", "alpha": "double", "beta": "double", "gamma": "double", "state": {"type": "record", "name": "Record", "fields": [{"name": "level", "type": "double"}, {"name": "trend", "type": "double"}, {"name": "cycle", "type": {"type": "array", "items": "double"}}, {"name": "multiplicative", "type": "boolean"}]}, None: "Record"}}, {"value": {"beta": 1.0001}, "domain": lambda x, alpha, beta, gamma, state: True, "type": {"x": "double", "alpha": "double", "beta": "double", "gamma": "double", "state": {"type": "record", "name": "Record", "fields": [{"name": "level", "type": "double"}, {"name": "trend", "type": "double"}, {"name": "cycle", "type": {"type": "array", "items": "double"}}, {"name": "multiplicative", "type": "boolean"}]}, None: "Record"}}],
    # stat.sample.updateHoltWintersPeriodic: If <p>gamma</p> is less than 0 or greater than 1, an "gamma out of range" error is raised.
    14052: [{"value": {"gamma": -0.0001}, "domain": lambda x, alpha, beta, gamma, state: True, "type": {"x": "double", "alpha": "double", "beta": "double", "gamma": "double", "state": {"type": "record", "name": "Record", "fields": [{"name": "level", "type": "double"}, {"name": "trend", "type": "double"}, {"name": "cycle", "type": {"type": "array", "items": "double"}}, {"name": "multiplicative", "type": "boolean"}]}, None: "Record"}}, {"value": {"gamma": 1.0001}, "domain": lambda x, alpha, beta, gamma, state: True, "type": {"x": "double", "alpha": "double", "beta": "double", "gamma": "double", "state": {"type": "record", "name": "Record", "fields": [{"name": "level", "type": "double"}, {"name": "trend", "type": "double"}, {"name": "cycle", "type": {"type": "array", "items": "double"}}, {"name": "multiplicative", "type": "boolean"}]}, None: "Record"}}],
    # stat.sample.updateHoltWintersPeriodic: If <pf>cycle</pf> is empty, an "empty cycle" error is raised.
    14053: [{"value": {"state": {"level": 0, "trend": 0, "cycle": [], "multiplicative": False}}, "domain": lambda x, alpha, beta, gamma, state: True, "type": {"x": "double", "alpha": "double", "beta": "double", "gamma": "double", "state": {"type": "record", "name": "Record", "fields": [{"name": "level", "type": "double"}, {"name": "trend", "type": "double"}, {"name": "cycle", "type": {"type": "array", "items": "double"}}, {"name": "multiplicative", "type": "boolean"}]}, None: "Record"}}],
    # stat.sample.forecast1HoltWinters: If <pf>cycle</pf> is empty, an "empty cycle" error is raised.
    14060: [{"value": {"state": {"level": 0, "trend": 0, "cycle": [], "multiplicative": False}}, "domain": lambda state: True, "type": {"state": {"type": "record", "name": "Record", "fields": [{"name": "level", "type": "double"}, {"name": "trend", "type": "double"}, {"name": "cycle", "type": {"type": "array", "items": "double"}}, {"name": "multiplicative", "type": "boolean"}]}, None: "double"}}],
    # stat.sample.forecastHoltWinters: If <pf>cycle</pf> is empty, an "empty cycle" error is raised.
    14070: [{"value": {"state": {"level": 0, "trend": 0, "cycle": [], "multiplicative": False}}, "domain": lambda n, state: True, "type": {"n": "int", "state": {"type": "record", "name": "Record", "fields": [{"name": "level", "type": "double"}, {"name": "trend", "type": "double"}, {"name": "cycle", "type": {"type": "array", "items": "double"}}, {"name": "multiplicative", "type": "boolean"}]}, None: {"type": "array", "items": "double"}}}],
    # stat.sample.fillHistogram: If the length of <pf>values</pf> is not equal to <pf>numbins</pf> or the length of <pf>ranges</pf>, then a "wrong histogram size" error is raised.
    14080: [{"value": {"histogram": {"numbins": 5, "low": 0, "high": 1, "values": [1, 2, 3, 4]}}, "domain": lambda x, w, histogram: True, "type": {"x": "double", "w": "double", "histogram": {"type": "record", "name": "Record", "fields": [{"name": "numbins", "type": "int"}, {"name": "low", "type": "double"}, {"name": "high", "type": "double"}, {"name": "values", "type": {"type": "array", "items": "double"}}]}, None: "Record"}}, {"value": {"histogram": {"ranges": [[0, 1], [1, 2], [2, 3]], "values": [1, 2, 3, 4]}}, "domain": lambda x, w, histogram: True, "type": {"x": "double", "w": "double", "histogram": {"type": "record", "name": "Record", "fields": [{"name": "ranges", "type": {"type": "array", "items": {"type": "array", "items": "double"}}}, {"name": "values", "type": {"type": "array", "items": "double"}}]}, None: "Record"}}],
    # stat.sample.fillHistogram: If <pf>low</pf> is greater than or equal to <pf>high</pf>, then a "bad histogram range" error is raised.
    14081: [{"value": {"histogram": {"numbins": 4, "low": 3.14, "high": 3.14, "values": [1, 2, 3, 4]}}, "domain": lambda x, w, histogram: True, "type": {"x": "double", "w": "double", "histogram": {"type": "record", "name": "Record", "fields": [{"name": "numbins", "type": "int"}, {"name": "low", "type": "double"}, {"name": "high", "type": "double"}, {"name": "values", "type": {"type": "array", "items": "double"}}]}, None: "Record"}}, {"value": {"histogram": {"numbins": 4, "low": 3.14, "high": 2.2, "values": [1, 2, 3, 4]}}, "domain": lambda x, w, histogram: True, "type": {"x": "double", "w": "double", "histogram": {"type": "record", "name": "Record", "fields": [{"name": "numbins", "type": "int"}, {"name": "low", "type": "double"}, {"name": "high", "type": "double"}, {"name": "values", "type": {"type": "array", "items": "double"}}]}, None: "Record"}}],
    # stat.sample.fillHistogram: If <pf>numbins</pf> is less than 1 or <pf>binsize</pf> is equal to 0, then a "bad histogram scale" error is raised.
    14082: [{"value": {"histogram": {"numbins": 0, "low": 0, "high": 1, "values": []}}, "domain": lambda x, w, histogram: True, "type": {"x": "double", "w": "double", "histogram": {"type": "record", "name": "Record", "fields": [{"name": "numbins", "type": "int"}, {"name": "low", "type": "double"}, {"name": "high", "type": "double"}, {"name": "values", "type": {"type": "array", "items": "double"}}]}, None: "Record"}}, {"value": {"histogram": {"numbins": -1, "low": 0, "high": 1, "values": []}}, "domain": lambda x, w, histogram: True, "type": {"x": "double", "w": "double", "histogram": {"type": "record", "name": "Record", "fields": [{"name": "numbins", "type": "int"}, {"name": "low", "type": "double"}, {"name": "high", "type": "double"}, {"name": "values", "type": {"type": "array", "items": "double"}}]}, None: "Record"}}, {"value": {"histogram": {"low": 3.14, "binsize": 0, "values": [1, 2, 3, 4]}}, "domain": lambda x, w, histogram: True, "type": {"x": "double", "w": "double", "histogram": {"type": "record", "name": "Record", "fields": [{"name": "low", "type": "double"}, {"name": "binsize", "type": "double"}, {"name": "values", "type": {"type": "array", "items": "double"}}]}, None: "Record"}}],
    # stat.sample.fillHistogram: If <pf>ranges</pf> contains an array of doubles with length not equal to 2 or if the first element is greater than the second element, then a "bad histogram ranges" error is raised.
    14083: [{"value": {"histogram": {"ranges": [[0, 1], [1, 2], [2, 3], [3]], "values": [1, 2, 3, 4]}}, "domain": lambda x, w, histogram: True, "type": {"x": "double", "w": "double", "histogram": {"type": "record", "name": "Record", "fields": [{"name": "ranges", "type": {"type": "array", "items": {"type": "array", "items": "double"}}}, {"name": "values", "type": {"type": "array", "items": "double"}}]}, None: "Record"}}, {"value": {"histogram": {"ranges": [[0, 1], [1, 2], [2, 3], [3, 3]], "values": [1, 2, 3, 4]}}, "domain": lambda x, w, histogram: True, "type": {"x": "double", "w": "double", "histogram": {"type": "record", "name": "Record", "fields": [{"name": "ranges", "type": {"type": "array", "items": {"type": "array", "items": "double"}}}, {"name": "values", "type": {"type": "array", "items": "double"}}]}, None: "Record"}}, {"value": {"histogram": {"ranges": [[0, 1], [1, 2], [2, 3], [3, 2]], "values": [1, 2, 3, 4]}}, "domain": lambda x, w, histogram: True, "type": {"x": "double", "w": "double", "histogram": {"type": "record", "name": "Record", "fields": [{"name": "ranges", "type": {"type": "array", "items": {"type": "array", "items": "double"}}}, {"name": "values", "type": {"type": "array", "items": "double"}}]}, None: "Record"}}],
    # stat.sample.fillHistogram2d: If the length of <pf>values</pf> is not equal to <pf>xnumbins</pf> or the length of any element of <pf>values</pf> is not equal to <pf>ynumbins</pf>, then a "wrong histogram size" error is raised.
    14090: [{"value": {"histogram": {"xnumbins": 3, "xlow": 0, "xhigh": 1, "ynumbins": 4, "ylow": 0, "yhigh": 1, "values": [[1, 2, 3, 4], [1, 2, 3, 4]]}}, "domain": lambda x, y, w, histogram: True, "type": {"x": "double", "y": "double", "w": "double", "histogram": {"type": "record", "name": "Record", "fields": [{"name": "xnumbins", "type": "int"}, {"name": "xlow", "type": "double"}, {"name": "xhigh", "type": "double"}, {"name": "ynumbins", "type": "int"}, {"name": "ylow", "type": "double"}, {"name": "yhigh", "type": "double"}, {"name": "values", "type": {"type": "array", "items": {"type": "array", "items": "double"}}}]}, None: "Record"}}, {"value": {"histogram": {"xnumbins": 3, "xlow": 0, "xhigh": 1, "ynumbins": 4, "ylow": 0, "yhigh": 1, "values": [[1, 2, 3, 4], [1, 2, 3, 4], [1, 2, 3]]}}, "domain": lambda x, y, w, histogram: True, "type": {"x": "double", "y": "double", "w": "double", "histogram": {"type": "record", "name": "Record", "fields": [{"name": "xnumbins", "type": "int"}, {"name": "xlow", "type": "double"}, {"name": "xhigh", "type": "double"}, {"name": "ynumbins", "type": "int"}, {"name": "ylow", "type": "double"}, {"name": "yhigh", "type": "double"}, {"name": "values", "type": {"type": "array", "items": {"type": "array", "items": "double"}}}]}, None: "Record"}}],
    # stat.sample.fillHistogram2d: If <pf>xlow</pf> is greater than or equal to <pf>xhigh</pf> or if <pf>ylow</pf> is greater than or equal to <pf>yhigh</pf>, then a "bad histogram range" error is raised.
    14091: [{"value": {"histogram": {"xnumbins": 3, "xlow": 3.14, "xhigh": 3.14, "ynumbins": 4, "ylow": 0, "yhigh": 1, "values": [[1, 2, 3, 4], [1, 2, 3, 4], [1, 2, 3, 4]]}}, "domain": lambda x, y, w, histogram: True, "type": {"x": "double", "y": "double", "w": "double", "histogram": {"type": "record", "name": "Record", "fields": [{"name": "xnumbins", "type": "int"}, {"name": "xlow", "type": "double"}, {"name": "xhigh", "type": "double"}, {"name": "ynumbins", "type": "int"}, {"name": "ylow", "type": "double"}, {"name": "yhigh", "type": "double"}, {"name": "values", "type": {"type": "array", "items": {"type": "array", "items": "double"}}}]}, None: "Record"}}, {"value": {"histogram": {"xnumbins": 3, "xlow": 3.14, "xhigh": 2.2, "ynumbins": 4, "ylow": 0, "yhigh": 1, "values": [[1, 2, 3, 4], [1, 2, 3, 4], [1, 2, 3, 4]]}}, "domain": lambda x, y, w, histogram: True, "type": {"x": "double", "y": "double", "w": "double", "histogram": {"type": "record", "name": "Record", "fields": [{"name": "xnumbins", "type": "int"}, {"name": "xlow", "type": "double"}, {"name": "xhigh", "type": "double"}, {"name": "ynumbins", "type": "int"}, {"name": "ylow", "type": "double"}, {"name": "yhigh", "type": "double"}, {"name": "values", "type": {"type": "array", "items": {"type": "array", "items": "double"}}}]}, None: "Record"}}, {"value": {"histogram": {"xnumbins": 3, "xlow": 0, "xhigh": 1, "ynumbins": 4, "ylow": 3.14, "yhigh": 3.14, "values": [[1, 2, 3, 4], [1, 2, 3, 4], [1, 2, 3, 4]]}}, "domain": lambda x, y, w, histogram: True, "type": {"x": "double", "y": "double", "w": "double", "histogram": {"type": "record", "name": "Record", "fields": [{"name": "xnumbins", "type": "int"}, {"name": "xlow", "type": "double"}, {"name": "xhigh", "type": "double"}, {"name": "ynumbins", "type": "int"}, {"name": "ylow", "type": "double"}, {"name": "yhigh", "type": "double"}, {"name": "values", "type": {"type": "array", "items": {"type": "array", "items": "double"}}}]}, None: "Record"}}, {"value": {"histogram": {"xnumbins": 3, "xlow": 0, "xhigh": 1, "ynumbins": 4, "ylow": 3.14, "yhigh": 2.2, "values": [[1, 2, 3, 4], [1, 2, 3, 4], [1, 2, 3, 4]]}}, "domain": lambda x, y, w, histogram: True, "type": {"x": "double", "y": "double", "w": "double", "histogram": {"type": "record", "name": "Record", "fields": [{"name": "xnumbins", "type": "int"}, {"name": "xlow", "type": "double"}, {"name": "xhigh", "type": "double"}, {"name": "ynumbins", "type": "int"}, {"name": "ylow", "type": "double"}, {"name": "yhigh", "type": "double"}, {"name": "values", "type": {"type": "array", "items": {"type": "array", "items": "double"}}}]}, None: "Record"}}],
    # stat.sample.fillHistogram2d: If <pf>xnumbins</pf> is less than 1 or <pf>ynumbins</pf> is less than 1, then a "bad histogram scale" error is raised.
    14092: [{"value": {"histogram": {"xnumbins": -1, "xlow": 0, "xhigh": 1, "ynumbins": 4, "ylow": 0, "yhigh": 1, "values": []}}, "domain": lambda x, y, w, histogram: True, "type": {"x": "double", "y": "double", "w": "double", "histogram": {"type": "record", "name": "Record", "fields": [{"name": "xnumbins", "type": "int"}, {"name": "xlow", "type": "double"}, {"name": "xhigh", "type": "double"}, {"name": "ynumbins", "type": "int"}, {"name": "ylow", "type": "double"}, {"name": "yhigh", "type": "double"}, {"name": "values", "type": {"type": "array", "items": {"type": "array", "items": "double"}}}]}, None: "Record"}}, {"value": {"histogram": {"xnumbins": 3, "xlow": 0, "xhigh": 1, "ynumbins": -1, "ylow": 0, "yhigh": 1, "values": []}}, "domain": lambda x, y, w, histogram: True, "type": {"x": "double", "y": "double", "w": "double", "histogram": {"type": "record", "name": "Record", "fields": [{"name": "xnumbins", "type": "int"}, {"name": "xlow", "type": "double"}, {"name": "xhigh", "type": "double"}, {"name": "ynumbins", "type": "int"}, {"name": "ylow", "type": "double"}, {"name": "yhigh", "type": "double"}, {"name": "values", "type": {"type": "array", "items": {"type": "array", "items": "double"}}}]}, None: "Record"}}],
    # stat.change.updateTrigger: If any of <pf>numEvents</pf>, <pf>numRuns</pf>, <pf>currentRun</pf>, and <pf>longestRun</pf> are less than 0, a "counter out of range" error is raised.
    37000: [{"value": {"history": {"numEvents": -1, "numRuns": 0, "currentRun": 0, "longestRun": 0}}, "domain": lambda predicate, history: True, "type": {"predicate": "boolean", "history": {"type": "record", "name": "Record", "fields": [{"name": "numEvents", "type": "int"}, {"name": "numRuns", "type": "int"}, {"name": "currentRun", "type": "int"}, {"name": "longestRun", "type": "int"}]}, None: "Record"}}, {"value": {"history": {"numEvents": 0, "numRuns": -1, "currentRun": 0, "longestRun": 0}}, "domain": lambda predicate, history: True, "type": {"predicate": "boolean", "history": {"type": "record", "name": "Record", "fields": [{"name": "numEvents", "type": "int"}, {"name": "numRuns", "type": "int"}, {"name": "currentRun", "type": "int"}, {"name": "longestRun", "type": "int"}]}, None: "Record"}}, {"value": {"history": {"numEvents": 0, "numRuns": 0, "currentRun": -1, "longestRun": 0}}, "domain": lambda predicate, history: True, "type": {"predicate": "boolean", "history": {"type": "record", "name": "Record", "fields": [{"name": "numEvents", "type": "int"}, {"name": "numRuns", "type": "int"}, {"name": "currentRun", "type": "int"}, {"name": "longestRun", "type": "int"}]}, None: "Record"}}, {"value": {"history": {"numEvents": 0, "numRuns": 0, "currentRun": 0, "longestRun": -1}}, "domain": lambda predicate, history: True, "type": {"predicate": "boolean", "history": {"type": "record", "name": "Record", "fields": [{"name": "numEvents", "type": "int"}, {"name": "numRuns", "type": "int"}, {"name": "currentRun", "type": "int"}, {"name": "longestRun", "type": "int"}]}, None: "Record"}}],
    # model.reg.linear: The array signature raises a "misaligned coeff" error if any row of <pf>coeff</pf> does not have the same indexes as <p>datum</p>.
    31000: [{"value": {"datum": [1, 2, 3, 4], "model": {"coeff": [1, 2, 3], "const": 0}}, "domain": lambda datum, model: True, "type": {"datum": {"type": "array", "items": "double"}, "model": {"type": "record", "name": "Record", "fields": [{"name": "coeff", "type": {"type": "array", "items": "double"}}, {"name": "const", "type": "double"}]}, None: "double"}}, {"value": {"datum": [1, 2, 3, 4], "model": {"coeff": [[1, 2, 3, 4], [1, 2, 3], [1, 2, 3, 4]], "const": [1, 2, 3]}}, "domain": lambda datum, model: True, "type": {"datum": {"type": "array", "items": "double"}, "model": {"type": "record", "name": "Record", "fields": [{"name": "coeff", "type": {"type": "array", "items": {"type": "array", "items": "double"}}}, {"name": "const", "type": {"type": "array", "items": "double"}}]}, None: {"type": "array", "items": "double"}}}],
    # model.reg.linear: The array signature raises a "misaligned const" error if <pf>const</pf> does not have the same indexes as <p>coeff</p>.
    31001: [{"value": {"datum": [1, 2, 3, 4], "model": {"coeff": [[1, 2, 3, 4], [1, 2, 3, 4], [1, 2, 3, 4]], "const": [1, 2, 3, 4]}}, "domain": lambda datum, model: True, "type": {"datum": {"type": "array", "items": "double"}, "model": {"type": "record", "name": "Record", "fields": [{"name": "coeff", "type": {"type": "array", "items": {"type": "array", "items": "double"}}}, {"name": "const", "type": {"type": "array", "items": "double"}}]}, None: {"type": "array", "items": "double"}}}],
    # model.reg.linearVariance: The array signature raises a "misaligned covariance" error if any covariance matrix does not have the same indexes as <p>datum</p> plus the implicit index for a constant (last in array signature).
    31010: [{"value": {"datum": [1, 2, 3], "model": {"covar": [[1, 2, 3], [1, 2, 3], [1, 2, 3]]}}, "domain": lambda datum, model: True, "type": {"datum": {"type": "array", "items": "double"}, "model": {"type": "record", "name": "Record", "fields": [{"name": "covar", "type": {"type": "array", "items": {"type": "array", "items": "double"}}}]}, None: "double"}}, {"value": {"datum": [1, 2, 3], "model": {"covar": [[1, 2, 3, 0], [1, 2, 3, 0], [1, 2, 3, 0]]}}, "domain": lambda datum, model: True, "type": {"datum": {"type": "array", "items": "double"}, "model": {"type": "record", "name": "Record", "fields": [{"name": "covar", "type": {"type": "array", "items": {"type": "array", "items": "double"}}}]}, None: "double"}}, {"value": {"datum": [1, 2, 3], "model": {"covar": [[1, 2, 3, 0], [1, 2, 3, 0], [1, 2, 3], [1, 2, 3, 0]]}}, "domain": lambda datum, model: True, "type": {"datum": {"type": "array", "items": "double"}, "model": {"type": "record", "name": "Record", "fields": [{"name": "covar", "type": {"type": "array", "items": {"type": "array", "items": "double"}}}]}, None: "double"}}, {"value": {"datum": [1, 2, 3], "model": {"covar": [[[1, 2, 3], [1, 2, 3], [1, 2, 3]], [[1, 2, 3], [1, 2, 3], [1, 2, 3]]]}}, "domain": lambda datum, model: True, "type": {"datum": {"type": "array", "items": "double"}, "model": {"type": "record", "name": "Record", "fields": [{"name": "covar", "type": {"type": "array", "items": {"type": "array", "items": {"type": "array", "items": "double"}}}}]}, None: {"type": "array", "items": "double"}}}, {"value": {"datum": [1, 2, 3], "model": {"covar": [[[1, 2, 3, 0], [1, 2, 3, 0], [1, 2, 3, 0]], [[1, 2, 3, 0], [1, 2, 3, 0], [1, 2, 3, 0]]]}}, "domain": lambda datum, model: True, "type": {"datum": {"type": "array", "items": "double"}, "model": {"type": "record", "name": "Record", "fields": [{"name": "covar", "type": {"type": "array", "items": {"type": "array", "items": {"type": "array", "items": "double"}}}}]}, None: {"type": "array", "items": "double"}}}, {"value": {"datum": [1, 2, 3], "model": {"covar": [[[1, 2, 3, 0], [1, 2, 3, 0], [1, 2, 3], [1, 2, 3, 0]], [[1, 2, 3, 0], [1, 2, 3, 0], [1, 2, 3], [1, 2, 3, 0]]]}}, "domain": lambda datum, model: True, "type": {"datum": {"type": "array", "items": "double"}, "model": {"type": "record", "name": "Record", "fields": [{"name": "covar", "type": {"type": "array", "items": {"type": "array", "items": {"type": "array", "items": "double"}}}}]}, None: {"type": "array", "items": "double"}}}],
    # model.tree.simpleTest: Raises an "invalid comparison operator" if <pf>operator</pf> is not one of "==", "!=", "<", "<=", ">", ">=", "in", "notIn", "alwaysTrue", "alwaysFalse", "isMissing", "notMissing".
    32000: [{"value": {"datum": {"x": 1}, "comparison": {"field": "x", "operator": "?", "value": 12}}, "domain": lambda datum, comparison: True, "type": {"datum": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": "int"}]}, "comparison": {"type": "record", "name": "Record2", "fields": [{"name": "field", "type": {"type": "enum", "name": "ErrorEnum", "symbols": ["x"]}}, {"name": "operator", "type": "string"}, {"name": "value", "type": "int"}]}, None: "boolean"}}],
    # model.tree.simpleTest: Raises a "bad value type" if the <pf>field</pf> of <p>datum</p> and <tp>V</tp> are not both numbers and the <pf>field</pf> cannot be upcast to <tp>V</tp>.
    32001: [{"value": {"datum": {"x": 1}, "comparison": {"field": "x", "operator": ">", "value": "hello"}}, "domain": lambda datum, comparison: True, "type": {"datum": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": "int"}]}, "comparison": {"type": "record", "name": "Record2", "fields": [{"name": "field", "type": {"type": "enum", "name": "ErrorEnum", "symbols": ["x"]}}, {"name": "operator", "type": "string"}, {"name": "value", "type": "string"}]}, None: "boolean"}}],
    # model.tree.missingTest: Raises an "invalid comparison operator" if <pf>operator</pf> is not one of "==", "!=", "<", "<=", ">", ">=", "in", "notIn", "alwaysTrue", "alwaysFalse".
    32010: [{"value": {"datum": {"x": 1}, "comparison": {"field": "x", "operator": "?", "value": 12}}, "domain": lambda datum, comparison: True, "type": {"datum": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": "int"}]}, "comparison": {"type": "record", "name": "Record2", "fields": [{"name": "field", "type": {"type": "enum", "name": "ErrorEnum", "symbols": ["x"]}}, {"name": "operator", "type": "string"}, {"name": "value", "type": "int"}]}, None: ["null", "boolean"]}}],
    # model.tree.missingTest: Raises a "bad value type" if the <pf>field</pf> of <p>datum</p> and <tp>V</tp> are not both numbers and the <pf>field</pf> cannot be upcast to <tp>V</tp>.
    32011: [{"value": {"datum": {"x": 1}, "comparison": {"field": "x", "operator": ">", "value": "hello"}}, "domain": lambda datum, comparison: True, "type": {"datum": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": "int"}]}, "comparison": {"type": "record", "name": "Record2", "fields": [{"name": "field", "type": {"type": "enum", "name": "ErrorEnum", "symbols": ["x"]}}, {"name": "operator", "type": "string"}, {"name": "value", "type": "string"}]}, None: ["null", "boolean"]}}],
    # model.tree.compoundTest: If <p>operator</p> is not "and", "or", or "xor", an "unrecognized logical operator" error is raised.
    32020: [{"value": {"operator": "?"}, "domain": lambda datum, operator, comparisons, test: True, "type": {"datum": {"type": "record", "name": "Record1", "fields": []}, "operator": "string", "comparisons": {"type": "array", "items": {"type": "record", "name": "Record2", "fields": [{"name": "q", "type": "int"}]}}, "test": {"params": ["Record1", "Record2"], "ret": "boolean"}, None: "boolean"}}],
    # model.tree.surrogateTest: If all tests return <c>null</c>, this function raises a "no successful surrogate" error.
    32030: [{"value": {"comparisons": []}, "domain": lambda datum, comparisons, missingTest: True, "type": {"datum": {"type": "record", "name": "Record1", "fields": []}, "comparisons": {"type": "array", "items": {"type": "record", "name": "Record2", "fields": [{"name": "q", "type": "int"}]}}, "missingTest": {"params": ["Record1", "Record2"], "ret": ["null", "boolean"]}, None: "boolean"}}],
    # model.tree.simpleTree: Raises an "invalid comparison operator" if <pf>operator</pf> is not one of "==", "!=", "<", "<=", ">", ">=", "in", "notIn", "alwaysTrue", "alwaysFalse", "isMissing", "notMissing".
    32060: [{"value": {"datum": {"x": 1}, "treeNode": {"field": "x", "operator": "?", "value": 12, "pass": {"string": "yay"}, "fail": {"string": "boo"}}}, "domain": lambda datum, treeNode: True, "type": {"datum": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": "int"}]}, "treeNode": {"type": "record", "name": "Record2", "fields": [{"name": "field", "type": {"type": "enum", "name": "ErrorEnum", "symbols": ["x"]}}, {"name": "operator", "type": "string"}, {"name": "value", "type": "int"}, {"name": "pass", "type": ["string", "Record2"]}, {"name": "fail", "type": ["string", "Record2"]}]}, None: "string"}}],
    # model.tree.simpleTree: Raises a "bad value type" if the <pf>field</pf> of <p>datum</p> and <tp>V</tp> are not both numbers and the <pf>field</pf> cannot be upcast to <tp>V</tp>.
    32061: [{"value": {"datum": {"x": 1}, "treeNode": {"field": "x", "operator": ">", "value": "hello", "pass": {"string": "yay"}, "fail": {"string": "boo"}}}, "domain": lambda datum, treeNode: True, "type": {"datum": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": "int"}]}, "treeNode": {"type": "record", "name": "Record2", "fields": [{"name": "field", "type": {"type": "enum", "name": "ErrorEnum", "symbols": ["x"]}}, {"name": "operator", "type": "string"}, {"name": "value", "type": "string"}, {"name": "pass", "type": ["string", "Record2"]}, {"name": "fail", "type": ["string", "Record2"]}]}, None: "string"}}],
    # model.cluster.closest: Raises a "no clusters" error if <p>clusters</p> is empty.
    29000: [{"value": {"clusters": []}, "domain": lambda datum, clusters: True, "type": {"datum": {"type": "array", "items": "double"}, "clusters": {"type": "array", "items": {"type": "record", "name": "Record", "fields": [{"name": "center", "type": {"type": "array", "items": "double"}}]}}, None: "Record"}}],
    # model.cluster.closestN: If <p>n</p> is negative, an "n must be nonnegative" error will be raised.
    29010: [{"value": {"n": -1}, "domain": lambda n, datum, clusters: True, "type": {"n": "int", "datum": {"type": "array", "items": "double"}, "clusters": {"type": "array", "items": {"type": "record", "name": "Record", "fields": [{"name": "center", "type": {"type": "array", "items": "double"}}]}}, None: {"type": "array", "items": "Record"}}}],
    # model.cluster.randomSeeds: Raises a "k must be greater than zero" error if <p>k</p> is less than or equal to zero.
    29020: [{"value": {"k": 0}, "domain": lambda data, k, newCluster: True, "type": {"data": {"type": "array", "items": {"type": "array", "items": "double"}}, "k": "int", "newCluster": {"params": ["int", {"type": "array", "items": "double"}], "ret": {"type": "record", "name": "Record", "fields": [{"name": "center", "type": {"type": "array", "items": "double"}}]}}, None: {"type": "array", "items": "Record"}}}],
    # model.cluster.randomSeeds: Raises a "not enough unique points" error if <p>data</p> has fewer than <p>k</p> unique elements.
    29021: [{"value": {"data": [[1, 2, 3, 4], [1, 2, 3, 4]], "k": 3}, "domain": lambda data, k, newCluster: True, "type": {"data": {"type": "array", "items": {"type": "array", "items": "double"}}, "k": "int", "newCluster": {"params": ["int", {"type": "array", "items": "double"}], "ret": {"type": "record", "name": "Record", "fields": [{"name": "center", "type": {"type": "array", "items": "double"}}]}}, None: {"type": "array", "items": "Record"}}}],
    # model.cluster.randomSeeds: Raises a "dimensions of vectors do not match" error if the elements of <p>data</p> are not all the same size.
    29022: [{"value": {"data": [[1, 2, 3, 5], [1, 2, 3, 4], [1, 2, 3]], "k": 3}, "domain": lambda data, k, newCluster: True, "type": {"data": {"type": "array", "items": {"type": "array", "items": "double"}}, "k": "int", "newCluster": {"params": ["int", {"type": "array", "items": "double"}], "ret": {"type": "record", "name": "Record", "fields": [{"name": "center", "type": {"type": "array", "items": "double"}}]}}, None: {"type": "array", "items": "Record"}}}],
    # model.cluster.kmeansIteration: Raises a "no data" error if <p>data</p> is empty.
    29030: [{"value": {"data": []}, "domain": lambda data, clusters, metric, update: True, "type": {"data": {"type": "array", "items": {"type": "array", "items": "double"}}, "clusters": {"type": "array", "items": {"type": "record", "name": "Record", "fields": [{"name": "center", "type": {"type": "array", "items": "double"}}]}}, "metric": {"params": [{"type": "array", "items": "double"}, {"type": "array", "items": "double"}], "ret": "double"}, "update": {"params": [{"type": "array", "items": {"type": "array", "items": "double"}}, "Record"], "ret": "Record"}, None: {"type": "array", "items": "Record"}}}],
    # model.cluster.kmeansIteration: Raises a "no clusters" error if <p>clusters</p> is empty.
    29031: [{"value": {"clusters": []}, "domain": lambda data, clusters, metric, update: True, "type": {"data": {"type": "array", "items": {"type": "array", "items": "double"}}, "clusters": {"type": "array", "items": {"type": "record", "name": "Record", "fields": [{"name": "center", "type": {"type": "array", "items": "double"}}]}}, "metric": {"params": [{"type": "array", "items": "double"}, {"type": "array", "items": "double"}], "ret": "double"}, "update": {"params": [{"type": "array", "items": {"type": "array", "items": "double"}}, "Record"], "ret": "Record"}, None: {"type": "array", "items": "Record"}}}],
    # model.cluster.updateMean: Raises a "no data" error if <p>data</p> is empty.
    29040: [{"value": {"data": []}, "domain": lambda data, cluster, weight: True, "type": {"data": {"type": "array", "items": {"type": "array", "items": "double"}}, "cluster": {"type": "record", "name": "Record", "fields": [{"name": "center", "type": {"type": "array", "items": "double"}}]}, "weight": "double", None: "Record"}}],
    # model.cluster.updateMean: Raises a "dimensions of vectors do not match" error if all elements of <p>data</p> and the <p>cluster</p> center do not match.
    29041: [{"value": {"data": [[1, 2, 3, 4], [1, 2, 3, 4], [1, 2, 3]], "cluster": {"center": [1, 2, 3, 4]}}, "domain": lambda data, cluster, weight: True, "type": {"data": {"type": "array", "items": {"type": "array", "items": "double"}}, "cluster": {"type": "record", "name": "Record", "fields": [{"name": "center", "type": {"type": "array", "items": "double"}}]}, "weight": "double", None: "Record"}}],
    # model.neighbor.mean: If <p>points</p> is empty, a "not enough points" error will be raised.
    30000: [{"value": {"points": []}, "domain": lambda points: True, "type": {"points": {"type": "array", "items": {"type": "array", "items": "double"}}, None: {"type": "array", "items": "double"}}}],
    # model.neighbor.mean: If the <p>points</p> have different sizes, an "inconsistent dimensionality" error will be raised.
    30001: [{"value": {"points": [[1, 2, 3, 4], [1, 2, 3, 4], [1, 2, 3]]}, "domain": lambda points: True, "type": {"points": {"type": "array", "items": {"type": "array", "items": "double"}}, None: {"type": "array", "items": "double"}}}],
    # model.neighbor.nearestK: If <p>k</p> is negative, an "k must be nonnegative" error will be raised.
    30010: [{"value": {"k": -1}, "domain": lambda k, datum, codebook: True, "type": {"k": "int", "datum": {"type": "array", "items": "double"}, "codebook": {"type": "array", "items": {"type": "array", "items": "double"}}, None: {"type": "array", "items": {"type": "array", "items": "double"}}}}],
    # model.neighbor.nearestK: If arrays in the <p>codebook</p> or the <p>codebook</p> and the <p>datum</p> have different sizes (without a <p>metric</p>), an "inconsistent dimensionality" error will be raised.
    30011: [{"value": {"datum": [1, 2, 3, 4], "codebook": [[1, 2, 3, 4], [1, 2, 3]]}, "domain": lambda k, datum, codebook: True, "type": {"k": "int", "datum": {"type": "array", "items": "double"}, "codebook": {"type": "array", "items": {"type": "array", "items": "double"}}, None: {"type": "array", "items": {"type": "array", "items": "double"}}}}],
    # model.naive.gaussian: Raises a "datum and classModel misaligned" error if <p>datum</p> and <p>classModel</p> have different lengths, of if their keys if using the map signature don't match one to one.
    10000: [{"value": {"datum": [1, 2, 3], "classModel": [{"mean": 3.14, "variance": 0.1}, {"mean": 3.14, "variance": 0.1}]}, "domain": lambda datum, classModel: True, "type": {"datum": {"type": "array", "items": "double"}, "classModel": {"type": "array", "items": {"type": "record", "name": "Record", "fields": [{"name": "mean", "type": "double"}, {"name": "variance", "type": "double"}]}}, None: "double"}}, {"value": {"datum": {"one": 1, "two": 2, "three": 3}, "classModel": {"one": {"mean": 3.14, "variance": 0.1}, "two": {"mean": 3.14, "variance": 0.1}}}, "domain": lambda datum, classModel: True, "type": {"datum": {"type": "map", "values": "double"}, "classModel": {"type": "map", "values": {"type": "record", "name": "Record", "fields": [{"name": "mean", "type": "double"}, {"name": "variance", "type": "double"}]}}, None: "double"}}],
    # model.naive.gaussian: Raises a "variance less than or equal to zero" error if a variance inside of <p>classModel</p> is incorrectly specified.
    10001: [{"value": {"datum": [1, 2], "classModel": [{"mean": 3.14, "variance": 0.1}, {"mean": 3.14, "variance": 0}]}, "domain": lambda datum, classModel: True, "type": {"datum": {"type": "array", "items": "double"}, "classModel": {"type": "array", "items": {"type": "record", "name": "Record", "fields": [{"name": "mean", "type": "double"}, {"name": "variance", "type": "double"}]}}, None: "double"}}, {"value": {"datum": {"one": 1, "two": 2}, "classModel": {"one": {"mean": 3.14, "variance": 0.1}, "two": {"mean": 3.14, "variance": -0.1}}}, "domain": lambda datum, classModel: True, "type": {"datum": {"type": "map", "values": "double"}, "classModel": {"type": "map", "values": {"type": "record", "name": "Record", "fields": [{"name": "mean", "type": "double"}, {"name": "variance", "type": "double"}]}}, None: "double"}}],
    # model.naive.multinomial: Raises a "datum and classModel misaligned" error if when using the map signature the keys of <p>datum</p> and <p>classModel</p> don't match one to one, of if when using the array signature they are different lengths.
    10010: [{"value": {"datum": [1, 2, 3, 4], "classModel": [1, 2, 3]}, "domain": lambda datum, classModel: True, "type": {"datum": {"type": "array", "items": "double"}, "classModel": {"type": "array", "items": "double"}, None: "double"}}, {"value": {"datum": {"one": 1, "two": 2, "three": 3}, "classModel": {"one": 1, "two": 2}}, "domain": lambda datum, classModel: True, "type": {"datum": {"type": "map", "values": "double"}, "classModel": {"type": "map", "values": "double"}, None: "double"}}, {"value": {"datum": [1, 2, 3, 4], "classModel": {"values": [1, 2, 3]}}, "domain": lambda datum, classModel: True, "type": {"datum": {"type": "array", "items": "double"}, "classModel": {"type": "record", "name": "Record", "fields": [{"name": "values", "type": {"type": "array", "items": "double"}}]}, None: "double"}}, {"value": {"datum": {"one": 1, "two": 2, "three": 3}, "classModel": {"values": {"one": 1, "two": 2}}}, "domain": lambda datum, classModel: True, "type": {"datum": {"type": "map", "values": "double"}, "classModel": {"type": "record", "name": "Record", "fields": [{"name": "values", "type": {"type": "map", "values": "double"}}]}, None: "double"}}],
    # model.naive.multinomial: Raises a "classModel must be non-empty and strictly positive" error if classModel is empty or any items are less than or equal to zero.
    10011: [{"value": {"classModel": []}, "domain": lambda datum, classModel: True, "type": {"datum": {"type": "array", "items": "double"}, "classModel": {"type": "array", "items": "double"}, None: "double"}}, {"value": {"classModel": [1, 2, 0]}, "domain": lambda datum, classModel: True, "type": {"datum": {"type": "array", "items": "double"}, "classModel": {"type": "array", "items": "double"}, None: "double"}}, {"value": {"classModel": [1, 2, -3]}, "domain": lambda datum, classModel: True, "type": {"datum": {"type": "array", "items": "double"}, "classModel": {"type": "array", "items": "double"}, None: "double"}}, {"value": {"classModel": {}}, "domain": lambda datum, classModel: True, "type": {"datum": {"type": "map", "values": "double"}, "classModel": {"type": "map", "values": "double"}, None: "double"}}, {"value": {"classModel": {"one": 1, "two": 2, "three": 0}}, "domain": lambda datum, classModel: True, "type": {"datum": {"type": "map", "values": "double"}, "classModel": {"type": "map", "values": "double"}, None: "double"}}, {"value": {"classModel": {"one": 1, "two": 2, "three": -3}}, "domain": lambda datum, classModel: True, "type": {"datum": {"type": "map", "values": "double"}, "classModel": {"type": "map", "values": "double"}, None: "double"}}, {"value": {"classModel": {"values": []}}, "domain": lambda datum, classModel: True, "type": {"datum": {"type": "array", "items": "double"}, "classModel": {"type": "record", "name": "Record", "fields": [{"name": "values", "type": {"type": "array", "items": "double"}}]}, None: "double"}}, {"value": {"classModel": {"values": [1, 2, 0]}}, "domain": lambda datum, classModel: True, "type": {"datum": {"type": "array", "items": "double"}, "classModel": {"type": "record", "name": "Record", "fields": [{"name": "values", "type": {"type": "array", "items": "double"}}]}, None: "double"}}, {"value": {"classModel": {"values": [1, 2, -3]}}, "domain": lambda datum, classModel: True, "type": {"datum": {"type": "array", "items": "double"}, "classModel": {"type": "record", "name": "Record", "fields": [{"name": "values", "type": {"type": "array", "items": "double"}}]}, None: "double"}}, {"value": {"classModel": {"values": {}}}, "domain": lambda datum, classModel: True, "type": {"datum": {"type": "map", "values": "double"}, "classModel": {"type": "record", "name": "Record", "fields": [{"name": "values", "type": {"type": "map", "values": "double"}}]}, None: "double"}}, {"value": {"classModel": {"values": {"one": 1, "two": 2, "three": 0}}}, "domain": lambda datum, classModel: True, "type": {"datum": {"type": "map", "values": "double"}, "classModel": {"type": "record", "name": "Record", "fields": [{"name": "values", "type": {"type": "map", "values": "double"}}]}, None: "double"}}, {"value": {"classModel": {"values": {"one": 1, "two": 2, "three": -3}}}, "domain": lambda datum, classModel: True, "type": {"datum": {"type": "map", "values": "double"}, "classModel": {"type": "record", "name": "Record", "fields": [{"name": "values", "type": {"type": "map", "values": "double"}}]}, None: "double"}}],
    # model.naive.bernoulli: Raises a "probability in classModel cannot be less than 0 or greater than 1" error if a value in <p>classModel</p> is less than zero or greater than one.
    10020: [{"value": {"classModel": {"one": 1, "two": 2, "three": -0.0001}}, "domain": lambda datum, classModel: True, "type": {"datum": {"type": "array", "items": "string"}, "classModel": {"type": "map", "values": "double"}, None: "double"}}, {"value": {"classModel": {"one": 1, "two": 2, "three": 1.0001}}, "domain": lambda datum, classModel: True, "type": {"datum": {"type": "array", "items": "string"}, "classModel": {"type": "map", "values": "double"}, None: "double"}}, {"value": {"classModel": {"values": {"one": 1, "two": 2, "three": -0.0001}}}, "domain": lambda datum, classModel: True, "type": {"datum": {"type": "array", "items": "string"}, "classModel": {"type": "record", "name": "Record", "fields": [{"name": "values", "type": {"type": "map", "values": "double"}}]}, None: "double"}}, {"value": {"classModel": {"values": {"one": 1, "two": 2, "three": 1.0001}}}, "domain": lambda datum, classModel: True, "type": {"datum": {"type": "array", "items": "string"}, "classModel": {"type": "record", "name": "Record", "fields": [{"name": "values", "type": {"type": "map", "values": "double"}}]}, None: "double"}}],
    # model.neural.simpleLayers: Raises a "no layers" error if the length of model is zero.
    11000: [{"value": {"model": []}, "domain": lambda datum, model, activation: True, "type": {"datum": {"type": "array", "items": "double"}, "model": {"type": "array", "items": {"type": "record", "name": "Record", "fields": [{"name": "weights", "type": {"type": "array", "items": {"type": "array", "items": "double"}}}, {"name": "bias", "type": {"type": "array", "items": "double"}}]}}, "activation": {"params": ["double"], "ret": "double"}, None: {"type": "array", "items": "double"}}}],
    # model.neural.simpleLayers: Raises a "weights, bias, or datum misaligned" error if there is any misalignment between inputs and outputs through the layers of the network.
    11001: [{"value": {"datum": [1, 2, 3, 4], "model": [{"weights": [[1, 2, 3, 4], [1, 2, 3, 4], [1, 2, 3, 4], [1, 2, 3, 4]], "bias": [1, 2, 3, 4]}, {"weights": [[1, 2, 3, 4], [1, 2, 3, 4], [1, 2, 3, 4], [1, 2, 3, 4]], "bias": [1, 2, 3]}]}, "domain": lambda datum, model, activation: True, "type": {"datum": {"type": "array", "items": "double"}, "model": {"type": "array", "items": {"type": "record", "name": "Record", "fields": [{"name": "weights", "type": {"type": "array", "items": {"type": "array", "items": "double"}}}, {"name": "bias", "type": {"type": "array", "items": "double"}}]}}, "activation": {"params": ["double"], "ret": "double"}, None: {"type": "array", "items": "double"}}}, {"value": {"datum": [1, 2, 3, 4], "model": [{"weights": [[1, 2, 3, 4], [1, 2, 3, 4], [1, 2, 3, 4], [1, 2, 3, 4]], "bias": [1, 2, 3, 4]}, {"weights": [[1, 2, 3, 4], [1, 2, 3, 4], [1, 2, 3], [1, 2, 3, 4]], "bias": [1, 2, 3, 4]}]}, "domain": lambda datum, model, activation: True, "type": {"datum": {"type": "array", "items": "double"}, "model": {"type": "array", "items": {"type": "record", "name": "Record", "fields": [{"name": "weights", "type": {"type": "array", "items": {"type": "array", "items": "double"}}}, {"name": "bias", "type": {"type": "array", "items": "double"}}]}}, "activation": {"params": ["double"], "ret": "double"}, None: {"type": "array", "items": "double"}}}, {"value": {"datum": [1, 2, 3, 4], "model": [{"weights": [[1, 2, 3, 4], [1, 2, 3, 4], [1, 2, 3, 4], [1, 2, 3, 4]], "bias": [1, 2, 3, 4]}, {"weights": [[1, 2, 3, 4], [1, 2, 3, 4], [1, 2, 3, 4]], "bias": [1, 2, 3, 4]}]}, "domain": lambda datum, model, activation: True, "type": {"datum": {"type": "array", "items": "double"}, "model": {"type": "array", "items": {"type": "record", "name": "Record", "fields": [{"name": "weights", "type": {"type": "array", "items": {"type": "array", "items": "double"}}}, {"name": "bias", "type": {"type": "array", "items": "double"}}]}}, "activation": {"params": ["double"], "ret": "double"}, None: {"type": "array", "items": "double"}}}, {"value": {"datum": [1, 2, 3], "model": [{"weights": [[1, 2, 3, 4], [1, 2, 3, 4], [1, 2, 3, 4], [1, 2, 3, 4]], "bias": [1, 2, 3, 4]}, {"weights": [[1, 2, 3, 4], [1, 2, 3, 4], [1, 2, 3, 4], [1, 2, 3, 4]], "bias": [1, 2, 3, 4]}]}, "domain": lambda datum, model, activation: True, "type": {"datum": {"type": "array", "items": "double"}, "model": {"type": "array", "items": {"type": "record", "name": "Record", "fields": [{"name": "weights", "type": {"type": "array", "items": {"type": "array", "items": "double"}}}, {"name": "bias", "type": {"type": "array", "items": "double"}}]}}, "activation": {"params": ["double"], "ret": "double"}, None: {"type": "array", "items": "double"}}}],
    # model.svm.score: Raises a "no support vectors" error if the length of <p>negClass</p> and length of <p>posClass</p> is zero.
    12000: [{"value": {"model": {"const": 0, "posClass": [], "negClass": []}}, "domain": lambda datum, model, kernel: True, "type": {"datum": {"type": "array", "items": "double"}, "model": {"type": "record", "name": "Record1", "fields": [{"name": "const", "type": "double"}, {"name": "posClass", "type": {"type": "array", "items": {"type": "record", "name": "Record2", "fields": [{"name": "supVec", "type": {"type": "array", "items": "double"}}, {"name": "coeff", "type": "double"}]}}}, {"name": "negClass", "type": {"type": "array", "items": {"type": "record", "name": "Record3", "fields": [{"name": "supVec", "type": {"type": "array", "items": "double"}}, {"name": "coeff", "type": "double"}]}}}]}, "kernel": {"params": [{"type": "array", "items": "double"}, {"type": "array", "items": "double"}], "ret": "double"}, None: "double"}}],
    # model.svm.score: Raises a "support vectors must have same length as datum" error if the length of the support vectors is not the same as the length of <p>datum</p>.
    12001: [{"value": {"datum": [1, 2, 3, 4], "model": {"const": 0, "posClass": [{"supVec": [1, 2, 3, 4], "coeff": 0.1}], "negClass": [{"supVec": [1, 2, 3], "coeff": 0.1}]}}, "domain": lambda datum, model, kernel: True, "type": {"datum": {"type": "array", "items": "double"}, "model": {"type": "record", "name": "Record1", "fields": [{"name": "const", "type": "double"}, {"name": "posClass", "type": {"type": "array", "items": {"type": "record", "name": "Record2", "fields": [{"name": "supVec", "type": {"type": "array", "items": "double"}}, {"name": "coeff", "type": "double"}]}}}, {"name": "negClass", "type": {"type": "array", "items": {"type": "record", "name": "Record3", "fields": [{"name": "supVec", "type": {"type": "array", "items": "double"}}, {"name": "coeff", "type": "double"}]}}}]}, "kernel": {"params": [{"type": "array", "items": "double"}, {"type": "array", "items": "double"}], "ret": "double"}, None: "double"}}],
    # model.reg.gaussianProcess: If <p>table</p> is empty, a "table must have at least 1 entry" error is raised.
    31080: [
{"value": {"table": []},
 "domain": lambda x, table, krigingWeight, kernel: True,
 "type": {"x": "double", "table": {"type": "array", "items": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": "double"}, {"name": "to", "type": "double"}]}}, "krigingWeight": ["null", "double"], "kernel": {"params": [{"type": "array", "items": "double"}, {"type": "array", "items": "double"}], "ret": "double"}, None: "double"}},
{"value": {"table": []},
 "domain": lambda x, table, krigingWeight, kernel: True,
 "type": {"x": "double", "table": {"type": "array", "items": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": "double"}, {"name": "to", "type": {"type": "array", "items": "double"}}]}}, "krigingWeight": ["null", "double"], "kernel": {"params": [{"type": "array", "items": "double"}, {"type": "array", "items": "double"}], "ret": "double"}, None: {"type": "array", "items": "double"}}},
{"value": {"table": []},
 "domain": lambda x, table, krigingWeight, kernel: True,
 "type": {"x": {"type": "array", "items": "double"}, "table": {"type": "array", "items": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": {"type": "array", "items": "double"}}, {"name": "to", "type": "double"}]}}, "krigingWeight": ["null", "double"], "kernel": {"params": [{"type": "array", "items": "double"}, {"type": "array", "items": "double"}], "ret": "double"}, None: "double"}},
{"value": {"table": []},
 "domain": lambda x, table, krigingWeight, kernel: True,
 "type": {"x": {"type": "array", "items": "double"}, "table": {"type": "array", "items": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": {"type": "array", "items": "double"}}, {"name": "to", "type": {"type": "array", "items": "double"}}]}}, "krigingWeight": ["null", "double"], "kernel": {"params": [{"type": "array", "items": "double"}, {"type": "array", "items": "double"}], "ret": "double"}, None: {"type": "array", "items": "double"}}}],
    # model.reg.gaussianProcess: If <p>x</p> is an empty array, an "x must have at least 1 feature" error is raised.
    31081: [
{"value": {"x": []},
 "domain": lambda x, table, krigingWeight, kernel: True,
 "type": {"x": {"type": "array", "items": "double"}, "table": {"type": "array", "items": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": {"type": "array", "items": "double"}}, {"name": "to", "type": "double"}]}}, "krigingWeight": ["null", "double"], "kernel": {"params": [{"type": "array", "items": "double"}, {"type": "array", "items": "double"}], "ret": "double"}, None: "double"}},
{"value": {"x": []},
 "domain": lambda x, table, krigingWeight, kernel: True,
 "type": {"x": {"type": "array", "items": "double"}, "table": {"type": "array", "items": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": {"type": "array", "items": "double"}}, {"name": "to", "type": {"type": "array", "items": "double"}}]}}, "krigingWeight": ["null", "double"], "kernel": {"params": [{"type": "array", "items": "double"}, {"type": "array", "items": "double"}], "ret": "double"}, None: {"type": "array", "items": "double"}}}],
    # model.reg.gaussianProcess: If any <pf>x</pf> in the <p>table</p> has a different length than the input parameter <p>x</p>, a "table must have the same number of features as x" error is raised.
    31082: [
{"value": {"x": [1, 2, 3], "table": [{"x": [1, 2], "to": 3.14}]},
 "domain": lambda x, table, krigingWeight, kernel: True,
 "type": {"x": {"type": "array", "items": "double"}, "table": {"type": "array", "items": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": {"type": "array", "items": "double"}}, {"name": "to", "type": "double"}]}}, "krigingWeight": ["null", "double"], "kernel": {"params": [{"type": "array", "items": "double"}, {"type": "array", "items": "double"}], "ret": "double"}, None: "double"}},
{"value": {"x": [1, 2, 3], "table": [{"x": [1, 2], "to": [3.14, 3.14]}]},
 "domain": lambda x, table, krigingWeight, kernel: True,
 "type": {"x": {"type": "array", "items": "double"}, "table": {"type": "array", "items": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": {"type": "array", "items": "double"}}, {"name": "to", "type": {"type": "array", "items": "double"}}]}}, "krigingWeight": ["null", "double"], "kernel": {"params": [{"type": "array", "items": "double"}, {"type": "array", "items": "double"}], "ret": "double"}, None: {"type": "array", "items": "double"}}}],
    # model.reg.gaussianProcess: If any <pf>to</pf> in the <p>table</p> is an empty array, a "table outputs must have at least 1 dimension" error is raised.
    31083: [
{"value": {"x": 3.14, "table": [{"x": 3.14, "to": []}]},
 "domain": lambda x, table, krigingWeight, kernel: True,
 "type": {"x": "double", "table": {"type": "array", "items": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": "double"}, {"name": "to", "type": {"type": "array", "items": "double"}}]}}, "krigingWeight": ["null", "double"], "kernel": {"params": [{"type": "array", "items": "double"}, {"type": "array", "items": "double"}], "ret": "double"}, None: {"type": "array", "items": "double"}}},
{"value": {"x": [1, 2], "table": [{"x": [1, 2], "to": []}]},
 "domain": lambda x, table, krigingWeight, kernel: True,
 "type": {"x": {"type": "array", "items": "double"}, "table": {"type": "array", "items": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": {"type": "array", "items": "double"}}, {"name": "to", "type": {"type": "array", "items": "double"}}]}}, "krigingWeight": ["null", "double"], "kernel": {"params": [{"type": "array", "items": "double"}, {"type": "array", "items": "double"}], "ret": "double"}, None: {"type": "array", "items": "double"}}}],
    # model.reg.gaussianProcess: If the <pf>to</pf> fields in <p>table</p> do not all have the same dimensions, a "table outputs must all have the same number of dimensions" error is raised.
    31084: [
{"value": {"x": 3.14, "table": [{"x": 3.14, "to": [1, 2]}, {"x": 3.14, "to": [1, 2, 3]}]},
 "domain": lambda x, table, krigingWeight, kernel: True,
 "type": {"x": "double", "table": {"type": "array", "items": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": "double"}, {"name": "to", "type": {"type": "array", "items": "double"}}]}}, "krigingWeight": ["null", "double"], "kernel": {"params": [{"type": "array", "items": "double"}, {"type": "array", "items": "double"}], "ret": "double"}, None: {"type": "array", "items": "double"}}},
{"value": {"x": [1, 2], "table": [{"x": [1, 2], "to": [1, 2]}, {"x": [1, 2], "to": [1, 2, 3]}]},
 "domain": lambda x, table, krigingWeight, kernel: True,
 "type": {"x": {"type": "array", "items": "double"}, "table": {"type": "array", "items": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": {"type": "array", "items": "double"}}, {"name": "to", "type": {"type": "array", "items": "double"}}]}}, "krigingWeight": ["null", "double"], "kernel": {"params": [{"type": "array", "items": "double"}, {"type": "array", "items": "double"}], "ret": "double"}, None: {"type": "array", "items": "double"}}}],
    # model.reg.gaussianProcess: If <p>x</p> or a component of <p>x</p> is not finite, an "x is not finite" error is raised.
    31085: [
{"value": {"x": "nan"},
 "domain": lambda x, table, krigingWeight, kernel: True,
 "type": {"x": "double", "table": {"type": "array", "items": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": "double"}, {"name": "to", "type": "double"}]}}, "krigingWeight": ["null", "double"], "kernel": {"params": [{"type": "array", "items": "double"}, {"type": "array", "items": "double"}], "ret": "double"}, None: "double"}},
{"value": {"x": "inf"},
 "domain": lambda x, table, krigingWeight, kernel: True,
 "type": {"x": "double", "table": {"type": "array", "items": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": "double"}, {"name": "to", "type": {"type": "array", "items": "double"}}]}}, "krigingWeight": ["null", "double"], "kernel": {"params": [{"type": "array", "items": "double"}, {"type": "array", "items": "double"}], "ret": "double"}, None: {"type": "array", "items": "double"}}},
{"value": {"x": [1, 2, "-inf"]},
 "domain": lambda x, table, krigingWeight, kernel: True,
 "type": {"x": {"type": "array", "items": "double"}, "table": {"type": "array", "items": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": {"type": "array", "items": "double"}}, {"name": "to", "type": "double"}]}}, "krigingWeight": ["null", "double"], "kernel": {"params": [{"type": "array", "items": "double"}, {"type": "array", "items": "double"}], "ret": "double"}, None: "double"}},
{"value": {"x": [1, 2, "nan"]},
 "domain": lambda x, table, krigingWeight, kernel: True,
 "type": {"x": {"type": "array", "items": "double"}, "table": {"type": "array", "items": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": {"type": "array", "items": "double"}}, {"name": "to", "type": {"type": "array", "items": "double"}}]}}, "krigingWeight": ["null", "double"], "kernel": {"params": [{"type": "array", "items": "double"}, {"type": "array", "items": "double"}], "ret": "double"}, None: {"type": "array", "items": "double"}}}],
    # model.reg.gaussianProcess: If any value in the <p>table</p> is not finite, a "table value is not finite" error is raised.
    31086: [
{"value": {"table": [{"x": 3.14, "to": "nan"}]},
 "domain": lambda x, table, krigingWeight, kernel: True,
 "type": {"x": "double", "table": {"type": "array", "items": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": "double"}, {"name": "to", "type": "double"}]}}, "krigingWeight": ["null", "double"], "kernel": {"params": [{"type": "array", "items": "double"}, {"type": "array", "items": "double"}], "ret": "double"}, None: "double"}},
{"value": {"table": [{"x": "inf", "to": 3.14}]},
 "domain": lambda x, table, krigingWeight, kernel: True,
 "type": {"x": "double", "table": {"type": "array", "items": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": "double"}, {"name": "to", "type": "double"}]}}, "krigingWeight": ["null", "double"], "kernel": {"params": [{"type": "array", "items": "double"}, {"type": "array", "items": "double"}], "ret": "double"}, None: "double"}},
{"value": {"table": [{"x": 3.14, "to": [1, 2, "-inf"]}]},
 "domain": lambda x, table, krigingWeight, kernel: True,
 "type": {"x": "double", "table": {"type": "array", "items": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": "double"}, {"name": "to", "type": {"type": "array", "items": "double"}}]}}, "krigingWeight": ["null", "double"], "kernel": {"params": [{"type": "array", "items": "double"}, {"type": "array", "items": "double"}], "ret": "double"}, None: {"type": "array", "items": "double"}}},
{"value": {"table": [{"x": "nan", "to": [1, 2, 3]}]},
 "domain": lambda x, table, krigingWeight, kernel: True,
 "type": {"x": "double", "table": {"type": "array", "items": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": "double"}, {"name": "to", "type": {"type": "array", "items": "double"}}]}}, "krigingWeight": ["null", "double"], "kernel": {"params": [{"type": "array", "items": "double"}, {"type": "array", "items": "double"}], "ret": "double"}, None: {"type": "array", "items": "double"}}},
{"value": {"table": [{"x": [1, 2, 3], "to": "inf"}]},
 "domain": lambda x, table, krigingWeight, kernel: True,
 "type": {"x": {"type": "array", "items": "double"}, "table": {"type": "array", "items": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": {"type": "array", "items": "double"}}, {"name": "to", "type": "double"}]}}, "krigingWeight": ["null", "double"], "kernel": {"params": [{"type": "array", "items": "double"}, {"type": "array", "items": "double"}], "ret": "double"}, None: "double"}},
{"value": {"table": [{"x": [1, 2, "-inf"], "to": 3.14}]},
 "domain": lambda x, table, krigingWeight, kernel: True,
 "type": {"x": {"type": "array", "items": "double"}, "table": {"type": "array", "items": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": {"type": "array", "items": "double"}}, {"name": "to", "type": "double"}]}}, "krigingWeight": ["null", "double"], "kernel": {"params": [{"type": "array", "items": "double"}, {"type": "array", "items": "double"}], "ret": "double"}, None: "double"}},
{"value": {"table": [{"x": [1, 2, 3], "to": [1, 2, "nan"]}]},
 "domain": lambda x, table, krigingWeight, kernel: True,
 "type": {"x": {"type": "array", "items": "double"}, "table": {"type": "array", "items": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": {"type": "array", "items": "double"}}, {"name": "to", "type": {"type": "array", "items": "double"}}]}}, "krigingWeight": ["null", "double"], "kernel": {"params": [{"type": "array", "items": "double"}, {"type": "array", "items": "double"}], "ret": "double"}, None: {"type": "array", "items": "double"}}},
{"value": {"table": [{"x": [1, 2, "inf"], "to": [1, 2, 3]}]},
 "domain": lambda x, table, krigingWeight, kernel: True,
 "type": {"x": {"type": "array", "items": "double"}, "table": {"type": "array", "items": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": {"type": "array", "items": "double"}}, {"name": "to", "type": {"type": "array", "items": "double"}}]}}, "krigingWeight": ["null", "double"], "kernel": {"params": [{"type": "array", "items": "double"}, {"type": "array", "items": "double"}], "ret": "double"}, None: {"type": "array", "items": "double"}}}],
    # model.reg.gaussianProcess: If <p>krigingWeight</p> is a number but is not finite, a "krigingWeight is not finite" error is raised.
    31087: [
{"value": {"krigingWeight": {"double": "nan"}},
 "domain": lambda x, table, krigingWeight, kernel: True,
 "type": {"x": "double", "table": {"type": "array", "items": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": "double"}, {"name": "to", "type": "double"}]}}, "krigingWeight": ["null", "double"], "kernel": {"params": [{"type": "array", "items": "double"}, {"type": "array", "items": "double"}], "ret": "double"}, None: "double"}},
{"value": {"krigingWeight": {"double": "inf"}},
 "domain": lambda x, table, krigingWeight, kernel: True,
 "type": {"x": "double", "table": {"type": "array", "items": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": "double"}, {"name": "to", "type": {"type": "array", "items": "double"}}]}}, "krigingWeight": ["null", "double"], "kernel": {"params": [{"type": "array", "items": "double"}, {"type": "array", "items": "double"}], "ret": "double"}, None: {"type": "array", "items": "double"}}},
{"value": {"krigingWeight": {"double": "-inf"}},
 "domain": lambda x, table, krigingWeight, kernel: True,
 "type": {"x": {"type": "array", "items": "double"}, "table": {"type": "array", "items": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": {"type": "array", "items": "double"}}, {"name": "to", "type": "double"}]}}, "krigingWeight": ["null", "double"], "kernel": {"params": [{"type": "array", "items": "double"}, {"type": "array", "items": "double"}], "ret": "double"}, None: "double"}},
{"value": {"krigingWeight": {"double": "nan"}},
 "domain": lambda x, table, krigingWeight, kernel: True,
 "type": {"x": {"type": "array", "items": "double"}, "table": {"type": "array", "items": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": {"type": "array", "items": "double"}}, {"name": "to", "type": {"type": "array", "items": "double"}}]}}, "krigingWeight": ["null", "double"], "kernel": {"params": [{"type": "array", "items": "double"}, {"type": "array", "items": "double"}], "ret": "double"}, None: {"type": "array", "items": "double"}}}],
    }

valueOverrides = {
    "m.special.nChooseK": {"n": [{"values": [10, 5, 2], "type": None}], "k": [{"values": [5, 1, 4, 9, -1, 10, 11], "type": None}]},
    "la.inverse": {"x": [{"values": [[[0.16, 1.15, -0.23], [-0.27, 0.3, -0.24], [0.03, -1.66, -1.07]], [[-1.97, -0.14, -1.03], [0.67, -0.23, -0.83], [-0.13, 2.19, 0.45]], [[0.88, 1.49, 1.29], [0.98, -1.08, -0.28], [-0.26, -1.46, -0.09]], [[-0.56, 0.42, -0.92], [-2.34, 1.63, 0.77], [0.86, -2.11, -0.1]]], "type": {"type": "array", "items": {"type": "array", "items": "double"}}}, {"values": [{"one": {"uno": 0.16, "dos": 1.15, "tres": -0.23}, "two": {"uno": -0.27, "dos": 0.3, "tres": -0.24}, "three": {"uno": 0.03, "dos": -1.66, "tres": -1.07}}, {"one": {"uno": -1.97, "dos": -0.14, "tres": -1.03}, "two": {"uno": 0.67, "dos": -0.23, "tres": -0.83}}, {"one": {"uno": 0.88, "dos": 1.49, "tres": 1.29}, "two": {"uno": 0.98, "dos": -1.08, "tres": -0.28}, "three": {"uno": -0.26, "dos": -1.46}}, {"one": {"uno": -0.56, "dos": 0.42, "tres": -0.92}, "two": {"uno": -2.34, "dos": 1.63, "TRES": 0.77}, "three": {"uno": 0.86, "dos": -2.11, "TRES": -0.1}}], "type": {"type": "map", "values": {"type": "map", "values": "double"}}}]},
    "metric.binarySimilarity": {"c00": [{"values": [0.0, 0.5, 1.0], "type": None}], "c01": [{"values": [0.0, 0.5, 1.0], "type": None}], "c10": [{"values": [0.0, 0.5, 1.0], "type": None}], "c11": [{"values": [0.0, 0.5, 1.0], "type": None}], "d00": [{"values": [0.0, 0.5, 1.0], "type": None}], "d01": [{"values": [0.0, 0.5, 1.0], "type": None}], "d10": [{"values": [0.0, 0.5, 1.0], "type": None}], "d11": [{"values": [0.0, 0.5, 1.0], "type": None}]},
    "rand.int": {"low": [{"values": [5, 10, 0, -5, -10], "type": None}], "high": [{"values": [10, 5, 0, -5, -10], "type": None}]},
    "rand.long": {"low": [{"values": [5, 10, 0, -5, -10], "type": None}], "high": [{"values": [10, 5, 0, -5, -10], "type": None}]},
    "rand.float": {"low": [{"values": [5.0, 10.0, 0.0, -5.0, -10.0], "type": None}], "high": [{"values": [10.0, 5.0, 0.0, -5.0, -10.0], "type": None}]},
    "rand.double": {"low": [{"values": [5.0, 10.0, 0.0, -5.0, -10.0], "type": None}], "high": [{"values": [10.0, 5.0, 0.0, -5.0, -10.0], "type": None}]},
    "rand.sample": {"size": [{"values": [2, 10, 0, 1], "type": None}]},
    "rand.string": {"low": [{"values": [32, 2, 1, 0, -1, 120, 200, 300, 5000], "type": None}], "high": [{"values": [64, 126, 210, 310, 55000, 66000], "type": None}]},
    "rand.bytes": {"low": [{"values": [32, 2, 1, 0, -1, 120, 200, 300], "type": None}], "high": [{"values": [64, 126, 210, 310], "type": None}]},
    "re.index": {"pattern": [{"values": ["ll", "l{2}", r"(.)\1"], "type": "string"}, {"values": [base64.b64encode("ll"), base64.b64encode("l{2}"), base64.b64encode(r"(.)\1")], "type": "bytes"}]},
    "re.contains": {"pattern": [{"values": ["ll", "l{2}", r"(.)\1"], "type": "string"}, {"values": [base64.b64encode("ll"), base64.b64encode("l{2}"), base64.b64encode(r"(.)\1")], "type": "bytes"}]},
    "re.count": {"pattern": [{"values": ["ll", "l{2}", r"(.)\1"], "type": "string"}, {"values": [base64.b64encode("ll"), base64.b64encode("l{2}"), base64.b64encode(r"(.)\1")], "type": "bytes"}]},
    "re.rindex": {"pattern": [{"values": ["ll", "l{2}", r"(.)\1"], "type": "string"}, {"values": [base64.b64encode("ll"), base64.b64encode("l{2}"), base64.b64encode(r"(.)\1")], "type": "bytes"}]},
    "re.groups": {"pattern": [{"values": ["ll", "l{2}", r"(.)\1"], "type": "string"}, {"values": [base64.b64encode("ll"), base64.b64encode("l{2}"), base64.b64encode(r"(.)\1")], "type": "bytes"}]},
    "re.indexall": {"pattern": [{"values": ["ll", "l{2}", r"(.)\1"], "type": "string"}, {"values": [base64.b64encode("ll"), base64.b64encode("l{2}"), base64.b64encode(r"(.)\1")], "type": "bytes"}]},
    "re.findall": {"pattern": [{"values": ["ll", "l{2}", r"(.)\1"], "type": "string"}, {"values": [base64.b64encode("ll"), base64.b64encode("l{2}"), base64.b64encode(r"(.)\1")], "type": "bytes"}]},
    "re.findfirst": {"pattern": [{"values": ["ll", "l{2}", r"(.)\1"], "type": "string"}, {"values": [base64.b64encode("ll"), base64.b64encode("l{2}"), base64.b64encode(r"(.)\1")], "type": "bytes"}]},
    "re.findgroupsfirst": {"pattern": [{"values": ["ll", "l{2}", r"(.)\1"], "type": "string"}, {"values": [base64.b64encode("ll"), base64.b64encode("l{2}"), base64.b64encode(r"(.)\1")], "type": "bytes"}]},
    "re.findgroupsall": {"pattern": [{"values": ["ll", "l{2}", r"(.)\1"], "type": "string"}, {"values": [base64.b64encode("ll"), base64.b64encode("l{2}"), base64.b64encode(r"(.)\1")], "type": "bytes"}]},
    "re.groupsall": {"pattern": [{"values": ["ll", "l{2}", r"(.)\1"], "type": "string"}, {"values": [base64.b64encode("ll"), base64.b64encode("l{2}"), base64.b64encode(r"(.)\1")], "type": "bytes"}]},
    "re.replacefirst": {"pattern": [{"values": ["ll", "l{2}", r"(.)\1"], "type": "string"}, {"values": [base64.b64encode("ll"), base64.b64encode("l{2}"), base64.b64encode(r"(.)\1")], "type": "bytes"}]},
    "re.replacelast": {"pattern": [{"values": ["ll", "l{2}", r"(.)\1"], "type": "string"}, {"values": [base64.b64encode("ll"), base64.b64encode("l{2}"), base64.b64encode(r"(.)\1")], "type": "bytes"}]},
    "re.split": {"pattern": [{"values": ["ll", "l{2}", r"(.)\1"], "type": "string"}, {"values": [base64.b64encode("ll"), base64.b64encode("l{2}"), base64.b64encode(r"(.)\1")], "type": "bytes"}]},
    "re.replaceall": {"pattern": [{"values": ["ll", "l{2}", r"(.)\1"], "type": "string"}, {"values": [base64.b64encode("ll"), base64.b64encode("l{2}"), base64.b64encode(r"(.)\1")], "type": "bytes"}]},
    "parse.int": {"base": [{"values": [10, 5, 16, 36, 2, 1, 0, -1, 37], "type": None}], "str": [{"values": ["314", "   314   ", " \n  314 \t  ", "-123", "ff", "-ff", ".-"], "type": None}]},
    "parse.long": {"base": [{"values": [10, 5, 16, 36, 2, 1, 0, -1, 37], "type": None}], "str": [{"values": ["314", "   314   ", " \n  314 \t  ", "-123", "ff", "-ff", ".-"], "type": None}]},
    "parse.float": {"str": [{"values": ["3.14", "   3.14   ", " \n  3.14 \t  ", "-123", "ff", "-ff", "3e12", "3E12"], "type": None}]},
    "parse.double": {"str": [{"values": ["3.14", "   3.14   ", " \n  3.14 \t  ", "-123", "ff", "-ff", "3e12", "3E12"], "type": None}]},
    "a.insert": {"index": [{"values": [2, 5, 1, 0, -1, -5, -2, -10], "type": None}]},
    "a.replace": {"index": [{"values": [2, 5, 1, 0, -1, -5, -2, -10], "type": None}]},
    "a.remove": {"index": [{"values": [2, 5, 1, 0, -1, -5, -2, -10], "type": None}]},
    "bytes.fromBase64": {"s": [{"values": ["aGVsbG8=", "..."], "type": None}]},
    "time.makeTimestamp": {"year": [{"values": [1970, 2000, 2016, 2300], "type": None}], "month": [{"values": [1, 2, 6, 12], "type": None}], "day": [{"values": [1, 15, 28, 29, 30, 31, 32], "type": None}], "hour": [{"values": [0, 23], "type": None}], "minute": [{"values": [0, 59], "type": None}], "second": [{"values": [0, 59], "type": None}], "millisecond": [{"values": [0, 999], "type": None}], "zone": [{"values": ["America/Chicago", "Etc/UTC"], "type": None}]},
    "time.year": {"zone": [{"values": ["America/Chicago", "Etc/UTC"], "type": None}]},
    "time.monthOfYear": {"zone": [{"values": ["America/Chicago", "Etc/UTC"], "type": None}]},
    "time.dayOfYear": {"zone": [{"values": ["America/Chicago", "Etc/UTC"], "type": None}]},
    "time.dayOfMonth": {"zone": [{"values": ["America/Chicago", "Etc/UTC"], "type": None}]},
    "time.dayOfWeek": {"zone": [{"values": ["America/Chicago", "Etc/UTC"], "type": None}]},
    "time.hourOfDay": {"zone": [{"values": ["America/Chicago", "Etc/UTC"], "type": None}]},
    "time.minuteOfHour": {"zone": [{"values": ["America/Chicago", "Etc/UTC"], "type": None}]},
    "time.secondOfMinute": {"zone": [{"values": ["America/Chicago", "Etc/UTC"], "type": None}]},
    "time.isSecondOfMinute": {"zone": [{"values": ["America/Chicago", "Etc/UTC"], "type": None}], "low": [{"values": [5.0, 1.0, 0.0, -1.0, -2.0, 23.0, 24.0, 59.0, 60.0, 27.0, 28.0, 29.0, 30.0, 31.0, 32.0], "type": None}], "high": [{"values": [6.0, 2.0, 1.0, 0.0, -1.0, 24.0, 25.0, 60.0, 61.0, 28.0, 29.0, 30.0, 31.0, 32.0, 33.0], "type": None}]},
    "time.isMinuteOfHour": {"zone": [{"values": ["America/Chicago", "Etc/UTC"], "type": None}], "low": [{"values": [5.0, 1.0, 0.0, -1.0, -2.0, 23.0, 24.0, 59.0, 60.0, 27.0, 28.0, 29.0, 30.0, 31.0, 32.0], "type": None}], "high": [{"values": [6.0, 2.0, 1.0, 0.0, -1.0, 24.0, 25.0, 60.0, 61.0, 28.0, 29.0, 30.0, 31.0, 32.0, 33.0], "type": None}]},
    "time.isHourOfDay": {"zone": [{"values": ["America/Chicago", "Etc/UTC"], "type": None}], "low": [{"values": [5.0, 1.0, 0.0, -1.0, -2.0, 23.0, 24.0, 59.0, 60.0, 27.0, 28.0, 29.0, 30.0, 31.0, 32.0], "type": None}], "high": [{"values": [6.0, 2.0, 1.0, 0.0, -1.0, 24.0, 25.0, 60.0, 61.0, 28.0, 29.0, 30.0, 31.0, 32.0, 33.0], "type": None}]},
    "time.isDayOfWeek": {"zone": [{"values": ["America/Chicago", "Etc/UTC"], "type": None}], "low": [{"values": [5.0, 1.0, 0.0, -1.0, -2.0, 23.0, 24.0, 59.0, 60.0, 27.0, 28.0, 29.0, 30.0, 31.0, 32.0], "type": None}], "high": [{"values": [6.0, 2.0, 1.0, 0.0, -1.0, 24.0, 25.0, 60.0, 61.0, 28.0, 29.0, 30.0, 31.0, 32.0, 33.0], "type": None}]},
    "time.isDayOfMonth": {"zone": [{"values": ["America/Chicago", "Etc/UTC"], "type": None}], "low": [{"values": [5.0, 1.0, 0.0, -1.0, -2.0, 23.0, 24.0, 59.0, 60.0, 27.0, 28.0, 29.0, 30.0, 31.0, 32.0], "type": None}], "high": [{"values": [6.0, 2.0, 1.0, 0.0, -1.0, 24.0, 25.0, 60.0, 61.0, 28.0, 29.0, 30.0, 31.0, 32.0, 33.0], "type": None}]},
    "time.isMonthOfYear": {"zone": [{"values": ["America/Chicago", "Etc/UTC"], "type": None}], "low": [{"values": [5.0, 1.0, 0.0, -1.0, -2.0, 23.0, 24.0, 59.0, 60.0, 27.0, 28.0, 29.0, 30.0, 31.0, 32.0], "type": None}], "high": [{"values": [6.0, 2.0, 1.0, 0.0, -1.0, 24.0, 25.0, 60.0, 61.0, 28.0, 29.0, 30.0, 31.0, 32.0, 33.0], "type": None}]},
    "time.isDayOfYear": {"zone": [{"values": ["America/Chicago", "Etc/UTC"], "type": None}], "low": [{"values": [5.0, 1.0, 0.0, -1.0, -2.0, 23.0, 24.0, 59.0, 60.0, 27.0, 28.0, 29.0, 30.0, 31.0, 32.0], "type": None}], "high": [{"values": [6.0, 2.0, 1.0, 0.0, -1.0, 24.0, 25.0, 60.0, 61.0, 28.0, 29.0, 30.0, 31.0, 32.0, 33.0], "type": None}]},
    "time.isWeekend": {"zone": [{"values": ["America/Chicago", "Etc/UTC"], "type": None}]},
    "time.isWorkHours": {"zone": [{"values": ["America/Chicago", "Etc/UTC"], "type": None}]},
    "impute.errorOnNull": {"x": [{"values": [{"double": 3.14}, None], "type": ["null", "double"]}]},
    "interp.bin": {"x": [{"values": [5.2, 1.0, 0.0, -1.0, -2.0, 23.0, 24.0, 59.0, 60.0, 27.0, 28.0, 29.0, 30.0, 31.0, 32.0], "type": None}], "low": [{"values": [5.0, 1.0, 0.0, -1.0, -2.0, 23.0, 24.0, 59.0, 60.0, 27.0, 28.0, 29.0, 30.0, 31.0, 32.0], "type": None}], "high": [{"values": [6.0, 2.0, 1.0, 0.0, -1.0, 24.0, 25.0, 60.0, 61.0, 28.0, 29.0, 30.0, 31.0, 32.0, 33.0], "type": None}]},
    "prob.dist.uniformPDF": {"x": [{"values": [5.2, 1.0, 0.0, -1.0, -2.0, 23.0, 24.0, 59.0, 60.0, 27.0, 28.0, 29.0, 30.0, 31.0, 32.0], "type": None}], "min": [{"values": [5.0, 1.0, 0.0, -1.0, -2.0, 23.0, 24.0, 59.0, 60.0, 27.0, 28.0, 29.0, 30.0, 31.0, 32.0], "type": None}], "max": [{"values": [6.0, 2.0, 1.0, 0.0, -1.0, 24.0, 25.0, 60.0, 61.0, 28.0, 29.0, 30.0, 31.0, 32.0, 33.0], "type": None}]},
    "prob.dist.uniformCDF": {"x": [{"values": [5.2, 1.0, 0.0, -1.0, -2.0, 23.0, 24.0, 59.0, 60.0, 27.0, 28.0, 29.0, 30.0, 31.0, 32.0], "type": None}], "min": [{"values": [5.0, 1.0, 0.0, -1.0, -2.0, 23.0, 24.0, 59.0, 60.0, 27.0, 28.0, 29.0, 30.0, 31.0, 32.0], "type": None}], "max": [{"values": [6.0, 2.0, 1.0, 0.0, -1.0, 24.0, 25.0, 60.0, 61.0, 28.0, 29.0, 30.0, 31.0, 32.0, 33.0], "type": None}]},
    "prob.dist.uniformQF": {"x": [{"values": [5.2, 1.0, 0.0, -1.0, -2.0, 23.0, 24.0, 59.0, 60.0, 27.0, 28.0, 29.0, 30.0, 31.0, 32.0], "type": None}], "min": [{"values": [5.0, 1.0, 0.0, -1.0, -2.0, 23.0, 24.0, 59.0, 60.0, 27.0, 28.0, 29.0, 30.0, 31.0, 32.0], "type": None}], "max": [{"values": [6.0, 2.0, 1.0, 0.0, -1.0, 24.0, 25.0, 60.0, 61.0, 28.0, 29.0, 30.0, 31.0, 32.0, 33.0], "type": None}]},
    "stat.test.mahalanobis": {"observation": [{"values": [[1.0, 2.0, 3.0], [2.0, -1.0, 0.0], [-0.27, 0.3, -0.24]], "type": {"type": "array", "items": "double"}}, {"values": [{"one": 1.0, "two": 2.0, "three": 3.0}, {"one": 2.0, "two": -1.0, "three": 0.0}, {"one": -0.27, "two": 0.3, "three": -0.24}], "type": {"type": "map", "values": "double"}}], "prediction": [{"values": [[2.0, -1.0, 0.0], [1.0, 2.0, 3.0], [-0.27, 0.3, -0.24]], "type": {"type": "array", "items": "double"}}, {"values": [{"one": 2.0, "two": -1.0, "three": 0.0}, {"one": 1.0, "two": 2.0, "three": 3.0}, {"one": -0.27, "two": 0.3, "three": -0.24}], "type": {"type": "map", "values": "double"}}], "covariance": [{"values": [[[0.16, 1.15, -0.23], [-0.27, 0.3, -0.24], [0.03, -1.66, -1.07]], [[-1.97, -0.14, -1.03], [0.67, -0.23, -0.83], [-0.13, 2.19, 0.45]], [[0.88, 1.49, 1.29], [0.98, -1.08, -0.28], [-0.26, -1.46, -0.09]], [[-0.56, 0.42, -0.92], [-2.34, 1.63, 0.77], [0.86, -2.11, -0.1]]], "type": {"type": "array", "items": {"type": "array", "items": "double"}}}, {"values": [{"one": {"one": 0.16, "two": 1.15, "three": -0.23}, "two": {"one": -0.27, "two": 0.3, "three": -0.24}, "three": {"one": 0.03, "two": -1.66, "three": -1.07}}, {"one": {"one": -1.97, "two": -0.14, "three": -1.03}, "two": {"one": 0.67, "two": -0.23, "three": -0.83}, "three": {"one": -0.67, "two": 0.23, "three": -0.83}}, {"one": {"one": 0.88, "two": 1.49, "three": 1.29}, "two": {"one": 0.98, "two": -1.08, "three": -0.28}, "three": {"one": -0.26, "two": -1.46, "three": 1.0}}, {"one": {"one": -0.56, "two": 0.42, "three": -0.92}, "two": {"one": -2.34, "two": 1.63, "three": 0.77}, "three": {"one": 0.86, "two": -2.11, "three": -0.1}}], "type": {"type": "map", "values": {"type": "map", "values": "double"}}}]},
    "stat.sample.updateWindow": {"windowSize": [{"values": [2, 3, 4], "type": None}], "state": [{"values": [[{"x": 1.1, "w": 1.0, "count": 1.0}, {"x": 2.2, "w": 1.0, "count": 1.0}, {"x": 3.3, "w": 2.0, "count": 1.0}], []], "type": {"items": {"fields": [{"type": "double", "name": "x"}, {"type": "double", "name": "w"}, {"type": "double", "name": "count"}], "type": "record", "name": "Record"}, "type": "array"}}, {"values": [[{"x": 1.1, "w": 1.0, "count": 1.0, "another": 3.14}, {"x": 2.2, "w": 1.0, "count": 1.0, "another": 3.14}, {"x": 3.3, "w": 2.0, "count": 1.0, "another": 3.14}], []] , "type": {"items": {"fields": [{"type": "double", "name": "x"}, {"type": "double", "name": "w"}, {"type": "double", "name": "count"}, {"type": "double", "name": "another"}], "type": "record", "name": "Record"}, "type": "array"}}], "x": [{"values": [4.4, 5.5], "type": None}], "w": [{"values": [-1.0, 0.0, 0.5, 1.0, 2.0], "type": None}]},
    "stat.sample.fillHistogram": {"histogram": [{"values": [{"low": -2.2, "high": 5.5, "numbins": 10, "values": [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]}, {"low": -2.2, "high": 5.5, "numbins": 10, "values": []}, {"low": "-inf", "high": 5.5, "numbins": 10, "values": [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]}, {"low": "nan", "high": 5.5, "numbins": 10, "values": [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]}, {"low": -2.2, "high": "inf", "numbins": 10, "values": [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]}, {"low": -2.2, "high": 5.5, "numbins": 10, "values": [0.0, 0.0, 0.0, "inf", 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]}, {"low": -2.2, "high": 5.5, "numbins": 10, "values": [0.0, 0.0, 0.0, "nan", 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]}], "type": {"fields": [{"type": "int", "name": "numbins"}, {"type": "double", "name": "low"}, {"type": "double", "name": "high"}, {"type": {"items": "double", "type": "array"}, "name": "values"}], "type": "record", "name": "Record"}}, {"values": [{"low": -2.2, "high": 5.5, "numbins": 10, "values": [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]}, {"low": -2.2, "high": 5.5, "numbins": 10, "values": []}, {"low": "-inf", "high": 5.5, "numbins": 10, "values": [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]}, {"low": "nan", "high": 5.5, "numbins": 10, "values": [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]}, {"low": -2.2, "high": "inf", "numbins": 10, "values": [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]}, {"low": -2.2, "high": 5.5, "numbins": 10, "values": [0.0, 0.0, 0.0, "inf", 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]}, {"low": -2.2, "high": 5.5, "numbins": 10, "values": [0.0, 0.0, 0.0, "nan", 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]}], "type": {"fields": [{"type": "int", "name": "numbins"}, {"type": "double", "name": "low"}, {"type": "double", "name": "high"}, {"type": {"items": "double", "type": "array"}, "name": "values"}], "type": "record", "name": "Record1"}}, {"values": [{"low": 17.0, "binsize": 0.0, "values": []}, {"low": 17.0, "binsize": 0.0, "values": [0.0]}, {"low": 17.0, "binsize": 0.0, "values": [1e-05, 0.99999]}, {"low": 17.0, "binsize": 0.0, "values": [1.0, 1.0, 1.00001, -1e-05, -0.99999, -1.0, -1.00001, 17.0, -17.0, 100.0, -100.0, 0.1, 0.5, 0.9, -0.1, -0.5, -0.9, "inf", "-inf", "nan", "nan"]}, {"low": 17.0, "binsize": 1.0, "values": []}, {"low": 17.0, "binsize": 1.0, "values": [0.0]}, {"low": 17.0, "binsize": 1.0, "values": [1e-05, 0.99999]}, {"low": 17.0, "binsize": 1.0, "values": [1.0, 1.0, 1.00001, -1e-05, -0.99999, -1.0, -1.00001, 17.0, -17.0, 100.0, -100.0, 0.1, 0.5, 0.9, -0.1, -0.5, -0.9, "inf", "-inf", "nan", "nan"]}, {"low": 17.0, "binsize": -1.0, "values": []}, {"low": 17.0, "binsize": -1.0, "values": [0.0]}, {"low": 17.0, "binsize": -1.0, "values": [1e-05, 0.99999]}, {"low": 17.0, "binsize": -1.0, "values": [1.0, 1.0, 1.00001, -1e-05, -0.99999, -1.0, -1.00001, 17.0, -17.0, 100.0, -100.0, 0.1, 0.5, 0.9, -0.1, -0.5, -0.9, "inf", "-inf", "nan", "nan"]}, {"low": 17.0, "binsize": 17.0, "values": []}, {"low": 17.0, "binsize": 17.0, "values": [0.0]}, {"low": 17.0, "binsize": 17.0, "values": [1e-05, 0.99999]}, {"low": 17.0, "binsize": 17.0, "values": [1.0, 1.0, 1.00001, -1e-05, -0.99999, -1.0, -1.00001, 17.0, -17.0, 100.0, -100.0, 0.1, 0.5, 0.9, -0.1, -0.5, -0.9, "inf", "-inf", "nan", "nan"]}, {"low": 17.0, "binsize": 100.0, "values": []}, {"low": 17.0, "binsize": 100.0, "values": [0.0]}, {"low": 17.0, "binsize": 100.0, "values": [1e-05, 0.99999]}, {"low": 17.0, "binsize": 100.0, "values": [1.0, 1.0, 1.00001, -1e-05, -0.99999, -1.0, -1.00001, 17.0, -17.0, 100.0, -100.0, 0.1, 0.5, 0.9, -0.1, -0.5, -0.9, "inf", "-inf", "nan", "nan"]}, {"low": 17.0, "binsize": "inf", "values": []}, {"low": 17.0, "binsize": "inf", "values": [0.0]}, {"low": 17.0, "binsize": "inf", "values": [1e-05, 0.99999]}, {"low": 17.0, "binsize": "inf", "values": [1.0, 1.0, 1.00001, -1e-05, -0.99999, -1.0, -1.00001, 17.0, -17.0, 100.0, -100.0, 0.1, 0.5, 0.9, -0.1, -0.5, -0.9, "inf", "-inf", "nan", "nan"]}, {"low": 17.0, "binsize": "-inf", "values": []}, {"low": 17.0, "binsize": "-inf", "values": [0.0]}, {"low": 17.0, "binsize": "-inf", "values": [1e-05, 0.99999]}, {"low": 17.0, "binsize": "-inf", "values": [1.0, 1.0, 1.00001, -1e-05, -0.99999, -1.0, -1.00001, 17.0, -17.0, 100.0, -100.0, 0.1, 0.5, 0.9, -0.1, -0.5, -0.9, "inf", "-inf", "nan", "nan"]}, {"low": 17.0, "binsize": "nan", "values": []}, {"low": 17.0, "binsize": "nan", "values": [0.0]}, {"low": 17.0, "binsize": "nan", "values": [1e-05, 0.99999]}, {"low": 17.0, "binsize": "nan", "values": [1.0, 1.0, 1.00001, -1e-05, -0.99999, -1.0, -1.00001, 17.0, -17.0, 100.0, -100.0, 0.1, 0.5, 0.9, -0.1, -0.5, -0.9, "inf", "-inf", "nan", "nan"]}], "type": {"fields": [{"type": "double", "name": "low"}, {"type": "double", "name": "binsize"}, {"type": {"items": "double", "type": "array"}, "name": "values"}], "type": "record", "name": "Record"}}, {"values": [{"low": 17.0, "binsize": 0.0, "values": []}, {"low": 17.0, "binsize": 0.0, "values": [0.0]}, {"low": 17.0, "binsize": 0.0, "values": [1e-05, 0.99999]}, {"low": 17.0, "binsize": 0.0, "values": [1.0, 1.0, 1.00001, -1e-05, -0.99999, -1.0, -1.00001, 17.0, -17.0, 100.0, -100.0, 0.1, 0.5, 0.9, -0.1, -0.5, -0.9, "inf", "-inf", "nan", "nan"]}, {"low": 17.0, "binsize": 1.0, "values": []}, {"low": 17.0, "binsize": 1.0, "values": [0.0]}, {"low": 17.0, "binsize": 1.0, "values": [1e-05, 0.99999]}, {"low": 17.0, "binsize": 1.0, "values": [1.0, 1.0, 1.00001, -1e-05, -0.99999, -1.0, -1.00001, 17.0, -17.0, 100.0, -100.0, 0.1, 0.5, 0.9, -0.1, -0.5, -0.9, "inf", "-inf", "nan", "nan"]}, {"low": 17.0, "binsize": -1.0, "values": []}, {"low": 17.0, "binsize": -1.0, "values": [0.0]}, {"low": 17.0, "binsize": -1.0, "values": [1e-05, 0.99999]}, {"low": 17.0, "binsize": -1.0, "values": [1.0, 1.0, 1.00001, -1e-05, -0.99999, -1.0, -1.00001, 17.0, -17.0, 100.0, -100.0, 0.1, 0.5, 0.9, -0.1, -0.5, -0.9, "inf", "-inf", "nan", "nan"]}, {"low": 17.0, "binsize": 17.0, "values": []}, {"low": 17.0, "binsize": 17.0, "values": [0.0]}, {"low": 17.0, "binsize": 17.0, "values": [1e-05, 0.99999]}, {"low": 17.0, "binsize": 17.0, "values": [1.0, 1.0, 1.00001, -1e-05, -0.99999, -1.0, -1.00001, 17.0, -17.0, 100.0, -100.0, 0.1, 0.5, 0.9, -0.1, -0.5, -0.9, "inf", "-inf", "nan", "nan"]}, {"low": 17.0, "binsize": 100.0, "values": []}, {"low": 17.0, "binsize": 100.0, "values": [0.0]}, {"low": 17.0, "binsize": 100.0, "values": [1e-05, 0.99999]}, {"low": 17.0, "binsize": 100.0, "values": [1.0, 1.0, 1.00001, -1e-05, -0.99999, -1.0, -1.00001, 17.0, -17.0, 100.0, -100.0, 0.1, 0.5, 0.9, -0.1, -0.5, -0.9, "inf", "-inf", "nan", "nan"]}, {"low": 17.0, "binsize": "inf", "values": []}, {"low": 17.0, "binsize": "inf", "values": [0.0]}, {"low": 17.0, "binsize": "inf", "values": [1e-05, 0.99999]}, {"low": 17.0, "binsize": "inf", "values": [1.0, 1.0, 1.00001, -1e-05, -0.99999, -1.0, -1.00001, 17.0, -17.0, 100.0, -100.0, 0.1, 0.5, 0.9, -0.1, -0.5, -0.9, "inf", "-inf", "nan", "nan"]}, {"low": 17.0, "binsize": "-inf", "values": []}, {"low": 17.0, "binsize": "-inf", "values": [0.0]}, {"low": 17.0, "binsize": "-inf", "values": [1e-05, 0.99999]}, {"low": 17.0, "binsize": "-inf", "values": [1.0, 1.0, 1.00001, -1e-05, -0.99999, -1.0, -1.00001, 17.0, -17.0, 100.0, -100.0, 0.1, 0.5, 0.9, -0.1, -0.5, -0.9, "inf", "-inf", "nan", "nan"]}, {"low": 17.0, "binsize": "nan", "values": []}, {"low": 17.0, "binsize": "nan", "values": [0.0]}, {"low": 17.0, "binsize": "nan", "values": [1e-05, 0.99999]}, {"low": 17.0, "binsize": "nan", "values": [1.0, 1.0, 1.00001, -1e-05, -0.99999, -1.0, -1.00001, 17.0, -17.0, 100.0, -100.0, 0.1, 0.5, 0.9, -0.1, -0.5, -0.9, "inf", "-inf", "nan", "nan"]}], "type": {"fields": [{"type": "double", "name": "low"}, {"type": "double", "name": "binsize"}, {"type": {"items": "double", "type": "array"}, "name": "values"}], "type": "record", "name": "Record1"}}, {"values": [{"values": [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], "ranges": [[0.0, 1.0], [1.0, 2.0], [3.0, 4.0], [5.0, 6.0], [0.0, 6.0], [-3.0, 2.2], [8.0, 9.0], [-100.0, 100.0], [-1.0, 0.0], [-2.0, -1.0]]}, {"values": [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], "ranges": [[0.0, 1.0], [1.0, "inf"], [3.0, 4.0], [5.0, 6.0], [0.0, 6.0], [-3.0, 2.2], [8.0, 9.0], [-100.0, 100.0], [-1.0, 0.0], [-2.0, -1.0]]}, {"values": [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], "ranges": [[0.0, 1.0], ["-inf", 2.0], [3.0, 4.0], [5.0, 6.0], [0.0, 6.0], [-3.0, 2.2], [8.0, 9.0], [-100.0, 100.0], [-1.0, 0.0], [-2.0, -1.0]]}, {"values": [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], "ranges": [[0.0, 1.0], ["nan", 2.0], [3.0, 4.0], [5.0, 6.0], [0.0, 6.0], [-3.0, 2.2], [8.0, 9.0], [-100.0, 100.0], [-1.0, 0.0], [-2.0, -1.0]]}, {"values": [], "ranges": [[0.0, 1.0], [1.0, 2.0], [3.0, 4.0], [5.0, 6.0], [0.0, 6.0], [-3.0, 2.2], [8.0, 9.0], [-100.0, 100.0], [-1.0, 0.0], [-2.0, -1.0]]}, {"values": [0.0, 0.0, "inf", 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], "ranges": [[0.0, 1.0], [1.0, 2.0], [3.0, 4.0], [5.0, 6.0], [0.0, 6.0], [-3.0, 2.2], [8.0, 9.0], [-100.0, 100.0], [-1.0, 0.0], [-2.0, -1.0]]}, {"values": [0.0, 0.0, "nan", 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], "ranges": [[0.0, 1.0], [1.0, 2.0], [3.0, 4.0], [5.0, 6.0], [0.0, 6.0], [-3.0, 2.2], [8.0, 9.0], [-100.0, 100.0], [-1.0, 0.0], [-2.0, -1.0]]}], "type": {"fields": [{"type": {"items": {"items": "double", "type": "array"}, "type": "array"}, "name": "ranges"}, {"type": {"items": "double", "type": "array"}, "name": "values"}], "type": "record", "name": "Record"}}, {"values": [{"values": [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], "ranges": [[0.0, 1.0], [1.0, 2.0], [3.0, 4.0], [5.0, 6.0], [0.0, 6.0], [-3.0, 2.2], [8.0, 9.0], [-100.0, 100.0], [-1.0, 0.0], [-2.0, -1.0]]}, {"values": [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], "ranges": [[0.0, 1.0], [1.0, "inf"], [3.0, 4.0], [5.0, 6.0], [0.0, 6.0], [-3.0, 2.2], [8.0, 9.0], [-100.0, 100.0], [-1.0, 0.0], [-2.0, -1.0]]}, {"values": [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], "ranges": [[0.0, 1.0], ["-inf", 2.0], [3.0, 4.0], [5.0, 6.0], [0.0, 6.0], [-3.0, 2.2], [8.0, 9.0], [-100.0, 100.0], [-1.0, 0.0], [-2.0, -1.0]]}, {"values": [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], "ranges": [[0.0, 1.0], ["nan", 2.0], [3.0, 4.0], [5.0, 6.0], [0.0, 6.0], [-3.0, 2.2], [8.0, 9.0], [-100.0, 100.0], [-1.0, 0.0], [-2.0, -1.0]]}, {"values": [], "ranges": [[0.0, 1.0], [1.0, 2.0], [3.0, 4.0], [5.0, 6.0], [0.0, 6.0], [-3.0, 2.2], [8.0, 9.0], [-100.0, 100.0], [-1.0, 0.0], [-2.0, -1.0]]}, {"values": [0.0, 0.0, "inf", 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], "ranges": [[0.0, 1.0], [1.0, 2.0], [3.0, 4.0], [5.0, 6.0], [0.0, 6.0], [-3.0, 2.2], [8.0, 9.0], [-100.0, 100.0], [-1.0, 0.0], [-2.0, -1.0]]}, {"values": [0.0, 0.0, "nan", 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], "ranges": [[0.0, 1.0], [1.0, 2.0], [3.0, 4.0], [5.0, 6.0], [0.0, 6.0], [-3.0, 2.2], [8.0, 9.0], [-100.0, 100.0], [-1.0, 0.0], [-2.0, -1.0]]}], "type": {"fields": [{"type": {"items": {"items": "double", "type": "array"}, "type": "array"}, "name": "ranges"}, {"type": {"items": "double", "type": "array"}, "name": "values"}], "type": "record", "name": "Record1"}}]},
    "stat.sample.fillHistogram2d": {"histogram": [{"values": [{"xnumbins": 3, "xlow": -2.2, "xhigh": 3.14, "ynumbins": 3, "ylow": 2.2, "yhigh": 6.28, "values": [[0.0, 0.0, 0.0], [0.0, 0.0, 0.0], [0.0, 0.0, 0.0]]}], "type": None}]},
    "model.tree.simpleTest": {"operator": [{"values": ["<", "<=", ">", ">=", "==", "!="], "type": None}]},
    "model.tree.missingTest": {"operator": [{"values": ["<", "<=", ">", ">=", "==", "!="], "type": None}]},
    "model.tree.compoundTest": {"operator": [{"values": ["and", "or", "xor"], "type": None}]},
    "model.tree.simpleWalk": {"datum": [{"values": [{"x": 1, "y": "whatever"}, {"x": 0, "y": "whatever"}, {"x": 7, "y": "TEST"}, {"x": 7, "y": "ZEST"}], "type": None}], "treeNode": [{"values": [{"pass": {"Record2": {"pass": {"int": 1}, "fail": {"int": 2}}}, "fail": {"Record2": {"pass": {"int": 3}, "fail": {"int": 4}}}}], "type": None}]},
    "model.tree.missingWalk": {"datum": [{"values": [{"x": 1, "y": "whatever"}, {"x": 0, "y": "whatever"}, {"x": 7, "y": "TEST"}, {"x": 7, "y": "ZEST"}], "type": None}], "treeNode": [{"values": [{"pass": {"Record2": {"pass": {"int": 1}, "fail": {"int": 2}, "missing": {"int": 3}}}, "fail": {"Record2": {"pass": {"int": 4}, "fail": {"int": 5}, "missing": {"int": 6}}}, "missing": {"Record2": {"pass": {"int": 7}, "fail": {"int": 8}, "missing": {"int": 9}}}}], "type": None}]},
    "model.tree.simpleTree": {"datum": [{"values": [{"x": 1}, {"x": 0}, {"x": 7}], "type": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": "int"}]}}], "treeNode": [{"values": [{"field": "x", "operator": "<", "value": 2, "pass": {"Record2": {"field": "x", "operator": "<", "value": 1, "pass": {"string": "1"}, "fail": {"string": "2"}}}, "fail": {"Record2": {"field": "x", "operator": "<", "value": 0, "pass": {"string": "3"}, "fail": {"string": "4"}}}}], "type": {"fields": [{"type": {"symbols": ["x"], "type": "enum", "name": "ErrorEnum"}, "name": "field"}, {"type": "string", "name": "operator"}, {"type": "int", "name": "value"}, {"type": ["string", "Record2"], "name": "pass"}, {"type": ["string", "Record2"], "name": "fail"}], "type": "record", "name": "Record2"}}, {"values": [{"field": "x", "operator": "<", "value": "2", "pass": {"Record2": {"field": "x", "operator": "<", "value": "1", "pass": {"string": "1"}, "fail": {"string": "2"}}}, "fail": {"Record2": {"field": "x", "operator": "<", "value": "0", "pass": {"string": "3"}, "fail": {"string": "4"}}}}], "type": {"fields": [{"type": {"symbols": ["x"], "type": "enum", "name": "ErrorEnum"}, "name": "field"}, {"type": "string", "name": "operator"}, {"type": "string", "name": "value"}, {"type": ["string", "Record2"], "name": "pass"}, {"type": ["string", "Record2"], "name": "fail"}], "type": "record", "name": "Record2"}}]}, 
    "model.cluster.randomSeeds": {"data": [{"values": [[[1, 2, 3], [1, 2, 0], [1, 2, 4], [1, -2, 3], [2, 1, 3], [0, 0, 1]]], "type": {"type": "array", "items": {"type": "array", "items": {"type": "array", "items": "int"}}}}, {"values": [[[1.1, 2.2, 3.0], [1.0, 2.1, 0.2], [1.0, 2.1, 4.8], [1.4, -2.1, 3.0], [2.2, 1.3, 3.4], [0.2, 0.4, 1.0]]], "type": {"type": "array", "items": {"type": "array", "items": {"type": "array", "items": "double"}}}}, {"values": [[[1.1, "-inf", 3.0], [1.0, 2.1, 0.2], [1.0, 2.1, 4.8], [1.4, -2.1, 3.0], [2.2, 1.3, 3.4], [0.2, 0.4, 1.0]]], "type": {"type": "array", "items": {"type": "array", "items": {"type": "array", "items": "double"}}}}, {"values": [[[1.1, "inf", 3.0], [1.0, 2.1, 0.2], [1.0, 2.1, 4.8], [1.4, -2.1, 3.0], [2.2, 1.3, 3.4], [0.2, 0.4, 1.0]]], "type": {"type": "array", "items": {"type": "array", "items": {"type": "array", "items": "double"}}}}, {"values": [[[1.1, "nan", 3.0], [1.0, 2.1, 0.2], [1.0, 2.1, 4.8], [1.4, -2.1, 3.0], [2.2, 1.3, 3.4], [0.2, 0.4, 1.0]]], "type": {"type": "array", "items": {"type": "array", "items": {"type": "array", "items": "double"}}}}, {"values": [[[1.2, 2.2, 3.0], [1.0, 2.1, 0.2], [1.0, 2.1, 4.8], [1.4, -2.1, 3.0], [2.2, 1.3, 3.4], [0.2, 0.4, 1.0]]], "type": {"type": "array", "items": {"type": "array", "items": "double"}}}, {"values": [[[1.2, "-inf", 3.0], [1.0, 2.1, 0.2], [1.0, 2.1, 4.8], [1.4, -2.1, 3.0], [2.2, 1.3, 3.4], [0.2, 0.4, 1.0]]], "type": {"type": "array", "items": {"type": "array", "items": "double"}}}, {"values": [[[1.2, "inf", 3.0], [1.0, 2.1, 0.2], [1.0, 2.1, 4.8], [1.4, -2.1, 3.0], [2.2, 1.3, 3.4], [0.2, 0.4, 1.0]]], "type": {"type": "array", "items": {"type": "array", "items": "double"}}}, {"values": [[[1.2, "nan", 3.0], [1.0, 2.1, 0.2], [1.0, 2.1, 4.8], [1.4, -2.1, 3.0], [2.2, 1.3, 3.4], [0.2, 0.4, 1.0]]], "type": {"type": "array", "items": {"type": "array", "items": "double"}}}, {"values": [[[1, 2, 3], [1, 2, 0], [1, 2, 4], [1, -2, 3], [2, 1, 3], [0, 0, 1]]], "type": {"type": "array", "items": {"type": "array", "items": "int"}}}, {"values": [[[["1", "2", "3"]], [["1", "2", "0"]], [["1", "2", "4"]], [["1", "-2", "3"]], [["2", "1", "3"]], [["0", "0", "1"]]]], "type": {"type": "array", "items": {"type": "array", "items": {"type": "array", "items": "string"}}}}, {"values": [[[None, {"double": 1.1}, None], [None, {"double": 2.2}, None], [None, {"double": 3.3}, None], [None, {"double": 4.4}, None], [None, {"double": 5.5}, None], [None, {"double": 6.6}, None]]], "type": {"type": "array", "items": {"type": "array", "items": ["null", "double"]}}}, {"values": [[[None, {"double": 1.1}, None], [None, {"double": "-inf"}, None], [None, {"double": 3.3}, None], [None, {"double": 4.4}, None], [None, {"double": 5.5}, None], [None, {"double": 6.6}, None]]], "type": {"type": "array", "items": {"type": "array", "items": ["null", "double"]}}}, {"values": [[[None, {"double": 1.1}, None], [None, {"double": "inf"}, None], [None, {"double": 3.3}, None], [None, {"double": 4.4}, None], [None, {"double": 5.5}, None], [None, {"double": 6.6}, None]]], "type": {"type": "array", "items": {"type": "array", "items": ["null", "double"]}}}, {"values": [[[None, {"double": 1.1}, None], [None, {"double": "nan"}, None], [None, {"double": 3.3}, None], [None, {"double": 4.4}, None], [None, {"double": 5.5}, None], [None, {"double": 6.6}, None]]], "type": {"type": "array", "items": {"type": "array", "items": ["null", "double"]}}}, {"values": [[[{"x": 1, "y": "1"}, {"x": 2, "y": "2"}], [{"x": 3, "y": "3"}, {"x": 4, "y": "4"}], [{"x": 5, "y": "5"}, {"x": 6, "y": "6"}], [{"x": 7, "y": "7"}, {"x": 8, "y": "8"}], [{"x": 9, "y": "9"}, {"x": 10, "y": "10"}], [{"x": 11, "y": "11"}, {"x": 12, "y": "12"}]]] , "type": {"type": "array", "items": {"type": "array", "items": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": "int"}, {"name": "y", "type": "string"}]}}}}]},
    "la.dot": {"x": [{"values": [[[1, 2, 3], [4, 5, 6], [7, 8, 9]], [[1, 2, 3], [4, "inf", 6], [7, 8, 9]], [[1, 2, 3], [4, "-inf", 6], [7, 8, 9]], [[1, 2, 3], [4, "nan", 6], [7, 8, 9]], [[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12]], [[1, 2, 3, 4], [5, "inf", 7, 8], [9, 10, 11, 12]], [[1, 2, 3, 4], [5, "-inf", 7, 8], [9, 10, 11, 12]], [[1, 2, 3, 4], [5, "nan", 7, 8], [9, 10, 11, 12]]], "type": {"type": "array", "items": {"type": "array", "items": "double"}}}], "y": [{"values": [[[1, 2, 3], [4, 5, 6], [7, 8, 9]], [[1, 2, 3], [4, "inf", 6], [7, 8, 9]], [[1, 2, 3], [4, "-inf", 6], [7, 8, 9]], [[1, 2, 3], [4, "nan", 6], [7, 8, 9]], [[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12]], [[1, 2, 3, 4], [5, "inf", 7, 8], [9, 10, 11, 12]], [[1, 2, 3, 4], [5, "-inf", 7, 8], [9, 10, 11, 12]], [[1, 2, 3, 4], [5, "nan", 7, 8], [9, 10, 11, 12]]], "type": {"type": "array", "items": {"type": "array", "items": "double"}}}]},
    "la.det": {"x": [{"values": [[[1, 2, 3], [4, 5, 6], [7, 8, 9]], [[1, 2, 3], [4, "inf", 6], [7, 8, 9]], [[1, 2, 3], [4, "-inf", 6], [7, 8, 9]], [[1, 2, 3], [4, "nan", 6], [7, 8, 9]]], "type": {"type": "array", "items": {"type": "array", "items": "double"}}}]},
    "la.symmetric": {"x": [{"values": [[[1, 2, 3], [4, 5, 6], [7, 8, 9]], [[1, 2, 3], [2, 5, 6], [3, 6, 9]], [[1, 2, 3], [2, "inf", 6], [3, 6, 9]], [[1, 2, 3], [2, "-inf", 6], [3, 6, 9]], [[1, 2, 3], [2, "nan", 6], [3, 6, 9]],], "type": {"type": "array", "items": {"type": "array", "items": "double"}}}]},
    "la.eigenBasis": {"x": [{"values": [[[1, 2, 3], [4, 5, 6], [7, 8, 9]], [[1, 2, 3], [4, "inf", 6], [7, 8, 9]], [[1, 2, 3], [4, "-inf", 6], [7, 8, 9]], [[1, 2, 3], [4, "nan", 6], [7, 8, 9]]], "type": {"type": "array", "items": {"type": "array", "items": "double"}}}]},
    "stat.sample.updateCovariance": {"x": [{"values": [[1, 2, 3], [1, 2, 3, 4], [1, 2, "inf", 4], [1, 2, "-inf", 4], [1, 2, "nan", 4]], "type": {"type": "array", "items": "double"}}], "mean": [{"values": [[1, 2, 3], [1, 2, 3, 4], [1, 2, "inf", 4], [1, 2, "-inf", 4], [1, 2, "nan", 4]], "type": {"type": "array", "items": "double"}}], "covariance": [{"values": [[[1, 2, 3], [4, 5, 6], [7, 8, 9]], [[1, 2, 3], [4, "inf", 6], [7, 8, 9]], [[1, 2, 3], [4, "-inf", 6], [7, 8, 9]], [[1, 2, 3], [4, "nan", 6], [7, 8, 9]], [[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12]], [[1, 2, 3, 4], [5, "inf", 7, 8], [9, 10, 11, 12]], [[1, 2, 3, 4], [5, "-inf", 7, 8], [9, 10, 11, 12]], [[1, 2, 3, 4], [5, "nan", 7, 8], [9, 10, 11, 12]]], "type": {"type": "array", "items": {"type": "array", "items": "double"}}}]},
    "model.reg.linearVariance": {"datum": [{"values": [[1, 2], [1, 2, 3], [1, 2, "inf"], [1, 2, "-inf"], [1, 2, "nan"]], "type": {"type": "array", "items": "double"}}], "covar": [{"values": [[[1, 2, 3], [4, 5, 6], [7, 8, 9]], [[1, 2, 3], [4, "inf", 6], [7, 8, 9]], [[1, 2, 3], [4, "-inf", 6], [7, 8, 9]], [[1, 2, 3], [4, "nan", 6], [7, 8, 9]], [[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12]], [[1, 2, 3, 4], [5, "inf", 7, 8], [9, 10, 11, 12]], [[1, 2, 3, 4], [5, "-inf", 7, 8], [9, 10, 11, 12]], [[1, 2, 3, 4], [5, "nan", 7, 8], [9, 10, 11, 12]]], "type": {"type": "array", "items": {"type": "array", "items": "double"}}}, {"values": [[[[1, 2, 3], [4, 5, 6], [7, 8, 9]]], [[[1, 2, 3], [4, "inf", 6], [7, 8, 9]]], [[[1, 2, 3], [4, "-inf", 6], [7, 8, 9]]], [[[1, 2, 3], [4, "nan", 6], [7, 8, 9]]], [[[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12]]], [[[1, 2, 3, 4], [5, "inf", 7, 8], [9, 10, 11, 12]]], [[[1, 2, 3, 4], [5, "-inf", 7, 8], [9, 10, 11, 12]]], [[[1, 2, 3, 4], [5, "nan", 7, 8], [9, 10, 11, 12]]]], "type": {"type": "array", "items": {"type": "array", "items": {"type": "array", "items": "double"}}}}]},
    }

def generateSimpleWalk():
    out = []
    for xType in ["int", {"type": "array", "items": "string"}]:
        for yType in ["int", {"type": "array", "items": "string"}]:
            for scoreType in ["int", {"type": "array", "items": "string"}, {"type": "record", "name": "Record3", "fields": [{"name": "x", "type": "int"}, {"name": "y", "type": "string"}]}]:
                if scoreType == "int":
                    output1, output2, output3, output4 = 0, -8, 12, 8
                    scoreName = "int"
                elif scoreType == {"type": "array", "items": "string"}:
                    output1, output2, output3, output4 = [], ["one"], ["one", "two"], ["one", "two", "three"]
                    scoreName = "array"
                elif scoreType == {"type": "record", "name": "Record3", "fields": [{"name": "x", "type": "int"}, {"name": "y", "type": "string"}]}:
                    output1, output2, output3, output4 = {"x": 1, "y": "one"}, {"x": 2, "y": "two"}, {"x": 3, "y": "three"}, {"x": 4, "y": "four"}
                    scoreName = "Record3"

                datumType = {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": xType}, {"name": "y", "type": yType}]}

                treeType = {"type": "record", "name": "Record2", "fields": [{"name": "pass", "type": ["Record2", scoreType]}, {"name": "fail", "type": ["Record2", scoreName if scoreName == "Record3" else scoreType]}]}

                treeValue = {"pass": {"Record2": {"pass": {scoreName: output1}, "fail": {scoreName: output2}}},
                             "fail": {"Record2": {"pass": {scoreName: output3}, "fail": {scoreName: output4}}}}

                if xType == "int":
                    testFunction = odict([("params", [{"d": "Record1"}, {"t": "Record2"}]), ("ret", "boolean"), ("do", {"<": ["d.x", 3]})])
                else:
                    testFunction = odict([("params", [{"d": "Record1"}, {"t": "Record2"}]), ("ret", "boolean"), ("do", {"<": [{"a.len": "d.x"}, 2]})])

                out.append((datumType, treeType, scoreName if scoreName == "Record3" else scoreType, treeValue, testFunction))
    return out

def generateMissingWalk():
    out = []
    for xType in ["int", {"type": "array", "items": "string"}]:
        for yType in ["int", {"type": "array", "items": "string"}]:
            for scoreType in ["int", {"type": "array", "items": "string"}, {"type": "record", "name": "Record3", "fields": [{"name": "x", "type": "int"}, {"name": "y", "type": "string"}]}]:
                if scoreType == "int":
                    output1, output2, output3, output4, output5, output6, output7, output8, output9 = -4, -3, -2, -1, 0, 1, 2, 3, 4
                    scoreName = "int"
                elif scoreType == {"type": "array", "items": "string"}:
                    output1, output2, output3, output4, output5, output6, output7, output8, output9 = [], ["one"], ["one", "two"], ["one", "two", "three"], ["one", "two", "three", "four"], ["one", "two", "three", "four", "five"], ["one", "two", "three", "four", "five", "six"], ["one", "two", "three", "four", "five", "six", "seven"],  ["one", "two", "three", "four", "five", "six", "seven", "eight"]
                    scoreName = "array"
                elif scoreType == {"type": "record", "name": "Record3", "fields": [{"name": "x", "type": "int"}, {"name": "y", "type": "string"}]}:
                    output1, output2, output3, output4, output5, output6, output7, output8, output9 = {"x": 1, "y": "one"}, {"x": 2, "y": "two"}, {"x": 3, "y": "three"}, {"x": 4, "y": "four"}, {"x": 5, "y": "five"}, {"x": 6, "y": "six"}, {"x": 7, "y": "seven"}, {"x": 8, "y": "eight"}, {"x": 9, "y": "nine"}
                    scoreName = "Record3"

                datumType = {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": xType}, {"name": "y", "type": yType}]}

                treeType = {"type": "record", "name": "Record2", "fields": [{"name": "pass", "type": ["Record2", scoreType]}, {"name": "fail", "type": ["Record2", scoreName if scoreName == "Record3" else scoreType]}, {"name": "missing", "type": ["Record2", scoreName if scoreName == "Record3" else scoreType]}]}

                treeValue = {"pass": {"Record2": {"pass": {scoreName: output1}, "fail": {scoreName: output2}, "missing": {scoreName: output3}}},
                             "fail": {"Record2": {"pass": {scoreName: output4}, "fail": {scoreName: output5}, "missing": {scoreName: output6}}},
                             "missing": {"Record2": {"pass": {scoreName: output7}, "fail": {scoreName: output8}, "missing": {scoreName: output9}}}}

                if xType == "int":
                    testFunction = odict([("params", [{"d": "Record1"}, {"t": "Record2"}]), ("ret", ["null", "boolean"]), ("do", {"if": {"<": ["d.x", 3]}, "then": None, "else": True})])
                else:
                    testFunction = odict([("params", [{"d": "Record1"}, {"t": "Record2"}]), ("ret", ["null", "boolean"]), ("do", {"if": {"<": [{"a.len": "d.x"}, 2]}, "then": None, "else": False})])

                out.append((datumType, treeType, scoreName if scoreName == "Record3" else scoreType, treeValue, testFunction))
    return out

def generateSimpleTree():
    out = []
    field1, field2, field3 = "x", "y", "x"
    for operator in "<", "==", "in", "isMissing":
        for xType in ["int", "string"]:
            for yType in ["int", "string"]:

                if operator == "<" or operator == "==":
                    if xType == yType:
                        valueType = xType
                        if valueType == "int":
                            value1, value2, value3 = 0, 5, 1
                        else:
                            value1, value2, value3 = u"", u"hello", u"oneee\u2212two"
                    else:
                        valueType = [xType, yType]
                        if xType == "int":
                            value1, value2, value3 = {"int": 0}, {"string": u"hello"}, {"int": 1}
                        else:
                            value1, value2, value3 = {"string": u""}, {"int": 5}, {"string": u"oneee\u2212two"}

                elif operator == "in":
                    if xType == yType:
                        valueType = {"type": "array", "items": xType}
                        if xType == "int":
                            value1, value2, value3 = [0, 1, 17, 5, 100], [2, -2, 5, -5, -100], []
                        else:
                            value1, value2, value3 = [u"", u"o", u"oneee\u2212two"], ["o", u"hello"], []

                    else:
                        continue

                elif operator == "isMissing":
                    valueType = "null"
                    value1, value2, value3 = None, None, None
                    if not isinstance(xType, list):
                        xType = ["null", xType]
                    if not isinstance(yType, list):
                        yType = ["null", yType]

                for scoreType in ["int", {"type": "array", "items": "string"}, {"type": "record", "name": "Record3", "fields": [{"name": "x", "type": "int"}, {"name": "y", "type": "string"}]}]:
                    if scoreType == "int":
                        output1, output2, output3, output4 = 0, -8, 12, 8
                        scoreName = "int"
                    elif scoreType == {"type": "array", "items": "string"}:
                        output1, output2, output3, output4 = [], ["one"], ["one", "two"], ["one", "two", "three"]
                        scoreName = "array"
                    elif scoreType == {"type": "record", "name": "Record3", "fields": [{"name": "x", "type": "int"}, {"name": "y", "type": "string"}]}:
                        output1, output2, output3, output4 = {"x": 1, "y": "one"}, {"x": 2, "y": "two"}, {"x": 3, "y": "three"}, {"x": 4, "y": "four"}
                        scoreName = "Record3"

                    datumType = {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": xType}, {"name": "y", "type": yType}]}

                    treeType = {"type": "record", "name": "Record2", "fields": [
                        {"name": "field", "type": {"symbols": ["x", "y"], "type": "enum", "name": "Enum"}},
                        {"name": "operator", "type": "string"},
                        {"name": "value", "type": valueType},
                        {"name": "pass", "type": ["Record2", scoreType]},
                        {"name": "fail", "type": ["Record2", scoreName if scoreName == "Record3" else scoreType]}]}

                    treeValue = {"field": field1, "operator": operator, "value": value1,
                                 "pass": {"Record2": {"field": field2, "operator": operator, "value": value2, "pass": {scoreName: output1}, "fail": {scoreName: output2}}},
                                 "fail": {"Record2": {"field": field3, "operator": operator, "value": value3, "pass": {scoreName: output3}, "fail": {scoreName: output4}}}}

                    out.append((datumType, treeType, scoreName if scoreName == "Record3" else scoreType, treeValue))
    return out

def skipThese(pfa):
    pfa = json.loads(pfa)
    if (pfa["function"] == "%" or pfa["function"] == "%%") and pfa["engine"]["output"] == "float":
        return True
    else:
        return False

if __name__ == "__main__":
    outputFileName, = sys.argv[1:]   # "pfa-tests.json"

    libfcns = xml.etree.ElementTree.parse(open("../libfcns.xml"))

    versionToTest = map(int, libfcns.find("./version").text.split("."))
    def okaySig(sig):
        return map(int, sig.attrib.get("birth", "0.0.0").split(".")) <= versionToTest and map(int, sig.attrib.get("deprecation", "999999.999999.999999").split(".")) > versionToTest

    go = False

    pfas = []
    for fcn in libfcns.findall("libfcns/fcn"):
        fcnName = fcn.attrib["name"]
        nondeterministic = None
        for x in fcn.findall("./doc/nondeterministic"):
            nondeterministic = x.attrib["type"]
        considered = set()

        nameOrders = []
        for sig in fcn.findall("./sig"):
            if okaySig(sig):
                nameOrders.append([x.attrib["name"] for x in sig.findall("./par")])
                
        if any(okaySig(sig) for sig in fcn.findall("./sig")):
            errors = fcn.findall("./doc/error")
            errs = {}
            for x in errors:
                code = int(x.attrib["code"])
                if code in errorConditions:
                    errs[code] = errorConditions[code]

            for errorCode, errorCases in errs.items():
                for errorCase in errorCases:
                    names = set(errorCase["type"].keys()) - set([None])
                    nameOrder = None
                    for x in nameOrders:
                        if set(x) == names:
                            nameOrder = x
                            break

                    if nameOrder is None:
                        print fcnName
                        print names
                        print "\n".join(map(repr, nameOrders))
                        raise Exception

                    types = odict()
                    for n in nameOrder:
                        t = errorCase["type"][n]
                        if isinstance(t, (dict, odict)) and "params" in t:
                            types[n] = Function(t["params"], t["ret"])
                        else:
                            types[n] = t

                    output = errorCase["type"][None]

                    nameLookup = {}
                    for t in types.values(): 
                        Signature.findNames(t, nameLookup)

                    signature = tuple([(k, Signature.makeHashable(v)) for k, v in types.items()] + [(None, Signature.makeHashable(output))])
                    if signature not in considered:
                        pfa = Signature.renderAsPFA(fcnName, valueOverrides, nameLookup, types, output, nondeterministic, errs, hint=errorCode)
                        if not skipThese(pfa):
                            print pfa
                            pfas.append(pfa)
                            considered.add(signature)

        for sig in fcn.findall("./sig"):
            if okaySig(sig):
                pat = Signature(sig)
                if fcnName == "model.tree.simpleWalk":
                    for datumType, treeType, scoreType, treeValue, testFunction in generateSimpleWalk():
                        types = odict()
                        types["datum"] = datumType
                        types["treeNode"] = treeType
                        output = scoreType

                        trials = []
                        for sample in Signature.generateValues(fcnName, {}, {"datum": datumType}, {}, {}):
                            trials.append("          " + json.dumps(odict([("sample", odict(sample, treeNode=treeValue)), ("result", "UNKNOWN_%07d" % Signature.unknownCounter)])))
                            Signature.unknownCounter += 1

                        pfa = Signature.formatPFA(types, output, fcnName, ['"input.datum"', '"input.treeNode"', json.dumps(testFunction)], trials)
                        if not skipThese(pfa):
                            print pfa
                            pfas.append(pfa)

                elif fcnName == "model.tree.missingWalk":
                    for datumType, treeType, scoreType, treeValue, testFunction in generateMissingWalk():
                        types = odict()
                        types["datum"] = datumType
                        types["treeNode"] = treeType
                        output = scoreType

                        trials = []
                        for sample in Signature.generateValues(fcnName, {}, {"datum": datumType}, {}, {}):
                            trials.append("          " + json.dumps(odict([("sample", odict(sample, treeNode=treeValue)), ("result", "UNKNOWN_%07d" % Signature.unknownCounter)])))
                            Signature.unknownCounter += 1

                        pfa = Signature.formatPFA(types, output, fcnName, ['"input.datum"', '"input.treeNode"', json.dumps(testFunction)], trials)
                        if not skipThese(pfa):
                            print pfa
                            pfas.append(pfa)

                elif fcnName == "model.tree.simpleTree":
                    for datumType, treeType, scoreType, treeValue in generateSimpleTree():
                        types = odict()
                        types["datum"] = datumType
                        types["treeNode"] = treeType
                        output = scoreType

                        trials = []
                        for sample in Signature.generateValues(fcnName, {}, {"datum": datumType}, {}, {}):
                            trials.append("          " + json.dumps(odict([("sample", odict(sample, treeNode=treeValue)), ("result", "UNKNOWN_%07d" % Signature.unknownCounter)])))
                            Signature.unknownCounter += 1

                        pfa = Signature.formatPFA(types, output, fcnName, ['"input.datum"', '"input.treeNode"'], trials)
                        if not skipThese(pfa):
                            print pfa
                            pfas.append(pfa)

                elif fcnName == "model.reg.gaussianProcess":
                    if isinstance(pat.parameters[0].pattern, Primitive) and pat.parameters[0].pattern.name == "double" and isinstance(pat.ret, Primitive) and pat.ret.name == "double":
                        types = odict([("x", "double"), ("krigingWeight", ["null", "double"])])
                        output = "double"
                        trials = []
                        for x in [-100, 35, 60, 95, 100]:
                            for krigingWeight in [None, {"double": 0.5}]:
                                trials.append("          " + json.dumps(odict([("sample", odict([("x", x), ("krigingWeight", krigingWeight)])), ("result", "UNKNOWN_%07d" % Signature.unknownCounter), ("nondeterministic", nondeterministic)])))
                                Signature.unknownCounter += 1
                        pfa = Signature.formatPFA(types, output, fcnName, ['"input.x"', '{"type": {"type": "array", "items": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": "double"}, {"name": "to", "type": "double"}, {"name": "sigma", "type": "double"}]}}, "value": [{"x":   0, "to": -0.3346332030, "sigma": 0.2}, {"x":  10, "to": -0.0343383864, "sigma": 0.2}, {"x":  20, "to": -0.0276927905, "sigma": 0.2}, {"x":  30, "to": 0.05708694575, "sigma": 0.2}, {"x":  40, "to": 0.66909595875, "sigma": 0.2}, {"x":  50, "to": 0.57458517677, "sigma": 0.2}, {"x":  60, "to": 0.63100196978, "sigma": 0.2}, {"x":  70, "to": 0.91841243688, "sigma": 0.2}, {"x":  80, "to": 0.65081764341, "sigma": 0.2}, {"x":  90, "to": 0.71978591756, "sigma": 0.2}, {"x": 100, "to": 0.93481331323, "sigma": 0.2}, {"x": 110, "to": 0.84831977376, "sigma": 0.2}, {"x": 120, "to": 0.73970609648, "sigma": 0.2}, {"x": 130, "to": 0.78029917594, "sigma": 0.2}, {"x": 140, "to": 0.65909346778, "sigma": 0.2}, {"x": 150, "to": 0.47746829475, "sigma": 0.2}, {"x": 160, "to": 0.15788020690, "sigma": 0.2}, {"x": 170, "to": -0.0417263190, "sigma": 0.2}, {"x": 180, "to": 0.03949032925, "sigma": 0.2}, {"x": 190, "to": -0.3433432642, "sigma": 0.2}, {"x": 200, "to": -0.0254098681, "sigma": 0.2}, {"x": 210, "to": -0.6289059981, "sigma": 0.2}, {"x": 220, "to": -0.7431731071, "sigma": 0.2}, {"x": 230, "to": -0.4354207032, "sigma": 0.2}, {"x": 240, "to": -1.0959618089, "sigma": 0.2}, {"x": 250, "to": -0.6671072982, "sigma": 0.2}, {"x": 260, "to": -0.9050596147, "sigma": 0.2}, {"x": 270, "to": -1.2019606762, "sigma": 0.2}, {"x": 280, "to": -1.1191287449, "sigma": 0.2}, {"x": 290, "to": -1.1299689439, "sigma": 0.2}, {"x": 300, "to": -0.5776687178, "sigma": 0.2}, {"x": 310, "to": -1.0480428012, "sigma": 0.2}, {"x": 320, "to": -0.6461742204, "sigma": 0.2}, {"x": 330, "to": -0.5866474699, "sigma": 0.2}, {"x": 340, "to": -0.3117119198, "sigma": 0.2}, {"x": 350, "to": -0.2478194617, "sigma": 0.2}]}', '"input.krigingWeight"', '{"fcn": "m.kernel.rbf", "fill": {"gamma": 2.0}}'], trials)
                        if not skipThese(pfa):
                            print pfa
                            pfas.append(pfa)

                    elif isinstance(pat.parameters[0].pattern, Primitive) and pat.parameters[0].pattern.name == "double" and isinstance(pat.ret, Array):
                        types = odict([("x", "double"), ("krigingWeight", ["null", "double"])])
                        output = odict([("type", "array"), ("items", "double")])
                        trials = []
                        for x in [-100, 35, 60, 95, 100]:
                            for krigingWeight in [None, {"double": 0.5}]:
                                trials.append("          " + json.dumps(odict([("sample", odict([("x", x), ("krigingWeight", krigingWeight)])), ("result", "UNKNOWN_%07d" % Signature.unknownCounter), ("nondeterministic", nondeterministic)])))
                                Signature.unknownCounter += 1
                        pfa = Signature.formatPFA(types, output, fcnName, ['"input.x"', '{"type": {"type": "array", "items": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": "double"}, {"name": "to", "type": {"type": "array", "items": "double"}}, {"name": "sigma", "type": {"type": "array", "items": "double"}}]}}, "value": [{"x":   0, "to": [-0.0275638306327, 1.6436104074682], "sigma": [0.2, 0.2]}, {"x":  10, "to": [-0.0550590156488, 1.1279026778761], "sigma": [0.2, 0.2]}, {"x":  20, "to": [0.27665811014276, 1.2884952019673], "sigma": [0.2, 0.2]}, {"x":  30, "to": [0.32564933012538, 0.6975167314472], "sigma": [0.2, 0.2]}, {"x":  40, "to": [0.50951585410170, 0.5366404828626], "sigma": [0.2, 0.2]}, {"x":  50, "to": [0.78970794409845, 0.5753573687864], "sigma": [0.2, 0.2]}, {"x":  60, "to": [0.79560759832648, 0.8669490726924], "sigma": [0.2, 0.2]}, {"x":  70, "to": [1.11012632091040, 0.2893283390564], "sigma": [0.2, 0.2]}, {"x":  80, "to": [1.01101991793607, 0.1168159075340], "sigma": [0.2, 0.2]}, {"x":  90, "to": [0.89167196367050, 0.2336483742367], "sigma": [0.2, 0.2]}, {"x": 100, "to": [0.79669701754334, -0.262415331320], "sigma": [0.2, 0.2]}, {"x": 110, "to": [0.73478042254427, -0.269257044570], "sigma": [0.2, 0.2]}, {"x": 120, "to": [0.54225961573755, -0.528524392539], "sigma": [0.2, 0.2]}, {"x": 130, "to": [0.63387009124588, -0.550031870271], "sigma": [0.2, 0.2]}, {"x": 140, "to": [0.53868855884699, -0.756608403729], "sigma": [0.2, 0.2]}, {"x": 150, "to": [0.52440311808591, -0.764908616789], "sigma": [0.2, 0.2]}, {"x": 160, "to": [0.38234791058889, -0.755332319548], "sigma": [0.2, 0.2]}, {"x": 170, "to": [0.06408032993876, -1.208343893027], "sigma": [0.2, 0.2]}, {"x": 180, "to": [-0.1251140497492, -1.008797566375], "sigma": [0.2, 0.2]}, {"x": 190, "to": [-0.6622773320724, -0.735977078508], "sigma": [0.2, 0.2]}, {"x": 200, "to": [-0.5060071246967, -1.131959607514], "sigma": [0.2, 0.2]}, {"x": 210, "to": [-0.7506697169187, -0.933266228609], "sigma": [0.2, 0.2]}, {"x": 220, "to": [-0.6114675918420, -1.115429627986], "sigma": [0.2, 0.2]}, {"x": 230, "to": [-0.7393428452701, -0.644829102596], "sigma": [0.2, 0.2]}, {"x": 240, "to": [-1.1005820484414, -0.602487247649], "sigma": [0.2, 0.2]}, {"x": 250, "to": [-0.9199172336156, -0.445415709796], "sigma": [0.2, 0.2]}, {"x": 260, "to": [-0.5548384390502, -0.130872144887], "sigma": [0.2, 0.2]}, {"x": 270, "to": [-1.1663758959153, 0.0403022656204], "sigma": [0.2, 0.2]}, {"x": 280, "to": [-1.3683792108867, -0.055259795527], "sigma": [0.2, 0.2]}, {"x": 290, "to": [-1.0373014259785, 0.1923335805121], "sigma": [0.2, 0.2]}, {"x": 300, "to": [-0.8539507289822, 0.6473186579626], "sigma": [0.2, 0.2]}, {"x": 310, "to": [-1.1658738130819, 0.7019580213786], "sigma": [0.2, 0.2]}, {"x": 320, "to": [-0.3248586082577, 0.5924413605916], "sigma": [0.2, 0.2]}, {"x": 330, "to": [-0.4246629811006, 0.7436475098601], "sigma": [0.2, 0.2]}, {"x": 340, "to": [-0.2888893157821, 0.9129729112785], "sigma": [0.2, 0.2]}, {"x": 350, "to": [0.16414946814559, 1.1171102512988], "sigma": [0.2, 0.2]}]}', '"input.krigingWeight"', '{"fcn": "m.kernel.rbf", "fill": {"gamma": 2.0}}'], trials)
                        if not skipThese(pfa):
                            print pfa
                            pfas.append(pfa)

                    elif isinstance(pat.parameters[0].pattern, Array) and isinstance(pat.ret, Primitive) and pat.ret.name == "double":
                        types = odict([("x", odict([("type", "array"), ("items", "double")])), ("krigingWeight", ["null", "double"])])
                        output = "double"
                        trials = []
                        for x1 in [-100, 35, 60, 95, 100]:
                            for x2 in [-100, 35, 60, 95, 100]:
                                for krigingWeight in [None, {"double": 0.5}]:
                                    trials.append("          " + json.dumps(odict([("sample", odict([("x", [x1, x2]), ("krigingWeight", krigingWeight)])), ("result", "UNKNOWN_%07d" % Signature.unknownCounter), ("nondeterministic", nondeterministic)])))
                                    Signature.unknownCounter += 1
                        pfa = Signature.formatPFA(types, output, fcnName, ['"input.x"', '{"type": {"type": "array", "items": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": {"type": "array", "items": "double"}}, {"name": "to", "type": "double"}, {"name": "sigma", "type": "double"}]}}, "value": [{"x": [  0,   0], "to": 0.82118528, "sigma": 0.2}, {"x": [  0,  36], "to": 0.63603407, "sigma": 0.2}, {"x": [  0,  72], "to": 0.43135014, "sigma": 0.2}, {"x": [  0, 108], "to": -0.5271264, "sigma": 0.2}, {"x": [  0, 144], "to": -0.7426378, "sigma": 0.2}, {"x": [  0, 180], "to": -1.1869050, "sigma": 0.2}, {"x": [  0, 216], "to": -0.7996154, "sigma": 0.2}, {"x": [  0, 252], "to": -0.4564504, "sigma": 0.2}, {"x": [  0, 288], "to": 0.08426291, "sigma": 0.2}, {"x": [  0, 324], "to": 0.80768845, "sigma": 0.2}, {"x": [ 36,   0], "to": 1.35803374, "sigma": 0.2}, {"x": [ 36,  36], "to": 1.52769845, "sigma": 0.2}, {"x": [ 36,  72], "to": 1.08079765, "sigma": 0.2}, {"x": [ 36, 108], "to": 0.31241499, "sigma": 0.2}, {"x": [ 36, 144], "to": -0.2676979, "sigma": 0.2}, {"x": [ 36, 180], "to": -0.7164726, "sigma": 0.2}, {"x": [ 36, 216], "to": -0.3338313, "sigma": 0.2}, {"x": [ 36, 252], "to": 0.08139820, "sigma": 0.2}, {"x": [ 36, 288], "to": 0.71689790, "sigma": 0.2}, {"x": [ 36, 324], "to": 1.13835037, "sigma": 0.2}, {"x": [ 72,   0], "to": 1.83512995, "sigma": 0.2}, {"x": [ 72,  36], "to": 1.61494407, "sigma": 0.2}, {"x": [ 72,  72], "to": 1.50290190, "sigma": 0.2}, {"x": [ 72, 108], "to": 0.75406155, "sigma": 0.2}, {"x": [ 72, 144], "to": 0.03405990, "sigma": 0.2}, {"x": [ 72, 180], "to": 0.14337997, "sigma": 0.2}, {"x": [ 72, 216], "to": 0.38604138, "sigma": 0.2}, {"x": [ 72, 252], "to": 0.36514719, "sigma": 0.2}, {"x": [ 72, 288], "to": 1.31043893, "sigma": 0.2}, {"x": [ 72, 324], "to": 1.63925281, "sigma": 0.2}, {"x": [108,   0], "to": 2.18498629, "sigma": 0.2}, {"x": [108,  36], "to": 1.36922627, "sigma": 0.2}, {"x": [108,  72], "to": 1.41108233, "sigma": 0.2}, {"x": [108, 108], "to": 0.80950036, "sigma": 0.2}, {"x": [108, 144], "to": 0.07678710, "sigma": 0.2}, {"x": [108, 180], "to": 0.03666408, "sigma": 0.2}, {"x": [108, 216], "to": -0.2375061, "sigma": 0.2}, {"x": [108, 252], "to": 0.57171030, "sigma": 0.2}, {"x": [108, 288], "to": 1.35875134, "sigma": 0.2}, {"x": [108, 324], "to": 1.64114251, "sigma": 0.2}, {"x": [144,   0], "to": 1.81406684, "sigma": 0.2}, {"x": [144,  36], "to": 1.36598027, "sigma": 0.2}, {"x": [144,  72], "to": 0.87335695, "sigma": 0.2}, {"x": [144, 108], "to": 0.28625228, "sigma": 0.2}, {"x": [144, 144], "to": -0.1884535, "sigma": 0.2}, {"x": [144, 180], "to": -0.7475230, "sigma": 0.2}, {"x": [144, 216], "to": 0.05916590, "sigma": 0.2}, {"x": [144, 252], "to": 0.20589299, "sigma": 0.2}, {"x": [144, 288], "to": 1.49434570, "sigma": 0.2}, {"x": [144, 324], "to": 1.04382638, "sigma": 0.2}, {"x": [180,   0], "to": 0.95695423, "sigma": 0.2}, {"x": [180,  36], "to": 0.99368592, "sigma": 0.2}, {"x": [180,  72], "to": 0.03288738, "sigma": 0.2}, {"x": [180, 108], "to": -0.6079039, "sigma": 0.2}, {"x": [180, 144], "to": -0.3848322, "sigma": 0.2}, {"x": [180, 180], "to": -1.0155591, "sigma": 0.2}, {"x": [180, 216], "to": -0.5555413, "sigma": 0.2}, {"x": [180, 252], "to": -0.0581398, "sigma": 0.2}, {"x": [180, 288], "to": 0.33743708, "sigma": 0.2}, {"x": [180, 324], "to": 0.83556571, "sigma": 0.2}, {"x": [216,   0], "to": 0.20588985, "sigma": 0.2}, {"x": [216,  36], "to": 0.44298549, "sigma": 0.2}, {"x": [216,  72], "to": -0.5446849, "sigma": 0.2}, {"x": [216, 108], "to": -1.0020396, "sigma": 0.2}, {"x": [216, 144], "to": -1.8021995, "sigma": 0.2}, {"x": [216, 180], "to": -1.5844545, "sigma": 0.2}, {"x": [216, 216], "to": -1.7084132, "sigma": 0.2}, {"x": [216, 252], "to": -0.9891052, "sigma": 0.2}, {"x": [216, 288], "to": -0.6297273, "sigma": 0.2}, {"x": [216, 324], "to": 0.26628269, "sigma": 0.2}, {"x": [252,   0], "to": 0.10807076, "sigma": 0.2}, {"x": [252,  36], "to": -0.4890686, "sigma": 0.2}, {"x": [252,  72], "to": -0.5842210, "sigma": 0.2}, {"x": [252, 108], "to": -1.2321703, "sigma": 0.2}, {"x": [252, 144], "to": -1.8977512, "sigma": 0.2}, {"x": [252, 180], "to": -2.1240163, "sigma": 0.2}, {"x": [252, 216], "to": -1.9555430, "sigma": 0.2}, {"x": [252, 252], "to": -1.5510880, "sigma": 0.2}, {"x": [252, 288], "to": -0.6289043, "sigma": 0.2}, {"x": [252, 324], "to": -0.2906448, "sigma": 0.2}, {"x": [288,   0], "to": 0.04032433, "sigma": 0.2}, {"x": [288,  36], "to": -0.0974952, "sigma": 0.2}, {"x": [288,  72], "to": -0.6059362, "sigma": 0.2}, {"x": [288, 108], "to": -1.4171517, "sigma": 0.2}, {"x": [288, 144], "to": -1.7699124, "sigma": 0.2}, {"x": [288, 180], "to": -2.1935099, "sigma": 0.2}, {"x": [288, 216], "to": -1.9860432, "sigma": 0.2}, {"x": [288, 252], "to": -1.1616088, "sigma": 0.2}, {"x": [288, 288], "to": -0.8162288, "sigma": 0.2}, {"x": [288, 324], "to": 0.16975848, "sigma": 0.2}, {"x": [324,   0], "to": 0.34328957, "sigma": 0.2}, {"x": [324,  36], "to": 0.26405396, "sigma": 0.2}, {"x": [324,  72], "to": -0.3641890, "sigma": 0.2}, {"x": [324, 108], "to": -0.9854455, "sigma": 0.2}, {"x": [324, 144], "to": -1.3019051, "sigma": 0.2}, {"x": [324, 180], "to": -1.6919030, "sigma": 0.2}, {"x": [324, 216], "to": -1.1601112, "sigma": 0.2}, {"x": [324, 252], "to": -0.9362727, "sigma": 0.2}, {"x": [324, 288], "to": -0.4371584, "sigma": 0.2}, {"x": [324, 324], "to": 0.17624777, "sigma": 0.2}]}', '"input.krigingWeight"', '{"fcn": "m.kernel.rbf", "fill": {"gamma": 2.0}}'], trials)
                        if not skipThese(pfa):
                            print pfa
                            pfas.append(pfa)

                    elif isinstance(pat.parameters[0].pattern, Array) and isinstance(pat.ret, Array):
                        types = odict([("x", odict([("type", "array"), ("items", "double")])), ("krigingWeight", ["null", "double"])])
                        output = odict([("type", "array"), ("items", "double")])
                        trials = []
                        for x1 in [-100, 35, 60, 95, 100]:
                            for x2 in [-100, 35, 60, 95, 100]:
                                for krigingWeight in [None, {"double": 0.5}]:
                                    trials.append("          " + json.dumps(odict([("sample", odict([("x", [x1, x2]), ("krigingWeight", krigingWeight)])), ("result", "UNKNOWN_%07d" % Signature.unknownCounter), ("nondeterministic", nondeterministic)])))
                                    Signature.unknownCounter += 1
                        pfa = Signature.formatPFA(types, output, fcnName, ['"input.x"', '{"type": {"type": "array", "items": {"type": "record", "name": "Record1", "fields": [{"name": "x", "type": {"type": "array", "items": "double"}}, {"name": "to", "type": {"type": "array", "items": "double"}}, {"name": "sigma", "type": {"type": "array", "items": "double"}}]}}, "value": [{"x": [  0,   0], "to": [0.01870587, 0.96812508], "sigma": [0.2, 0.2]}, {"x": [  0,  36], "to": [0.00242101, 0.95369720], "sigma": [0.2, 0.2]}, {"x": [  0,  72], "to": [0.13131668, 0.53822666], "sigma": [0.2, 0.2]}, {"x": [  0, 108], "to": [-0.0984303, -0.3743950], "sigma": [0.2, 0.2]}, {"x": [  0, 144], "to": [0.15985766, -0.6027780], "sigma": [0.2, 0.2]}, {"x": [  0, 180], "to": [-0.2417438, -1.0968682], "sigma": [0.2, 0.2]}, {"x": [  0, 216], "to": [0.05190623, -0.9102348], "sigma": [0.2, 0.2]}, {"x": [  0, 252], "to": [0.27249439, -0.4792263], "sigma": [0.2, 0.2]}, {"x": [  0, 288], "to": [0.07282733, 0.48063363], "sigma": [0.2, 0.2]}, {"x": [  0, 324], "to": [-0.0842266, 0.57112860], "sigma": [0.2, 0.2]}, {"x": [ 36,   0], "to": [0.47755174, 1.13094388], "sigma": [0.2, 0.2]}, {"x": [ 36,  36], "to": [0.41956515, 0.90267757], "sigma": [0.2, 0.2]}, {"x": [ 36,  72], "to": [0.59136153, 0.41456807], "sigma": [0.2, 0.2]}, {"x": [ 36, 108], "to": [0.60570628, -0.2181357], "sigma": [0.2, 0.2]}, {"x": [ 36, 144], "to": [0.59105899, -0.5619968], "sigma": [0.2, 0.2]}, {"x": [ 36, 180], "to": [0.57772703, -0.8929270], "sigma": [0.2, 0.2]}, {"x": [ 36, 216], "to": [0.23902551, -0.8220304], "sigma": [0.2, 0.2]}, {"x": [ 36, 252], "to": [0.61153563, -0.0519713], "sigma": [0.2, 0.2]}, {"x": [ 36, 288], "to": [0.64443777, 0.48040414], "sigma": [0.2, 0.2]}, {"x": [ 36, 324], "to": [0.48667517, 0.71326465], "sigma": [0.2, 0.2]}, {"x": [ 72,   0], "to": [1.09232448, 0.93827725], "sigma": [0.2, 0.2]}, {"x": [ 72,  36], "to": [0.81049592, 1.11762190], "sigma": [0.2, 0.2]}, {"x": [ 72,  72], "to": [0.71568727, 0.06369347], "sigma": [0.2, 0.2]}, {"x": [ 72, 108], "to": [0.72942906, -0.5640199], "sigma": [0.2, 0.2]}, {"x": [ 72, 144], "to": [1.06713767, -0.4772772], "sigma": [0.2, 0.2]}, {"x": [ 72, 180], "to": [1.38277511, -0.9363026], "sigma": [0.2, 0.2]}, {"x": [ 72, 216], "to": [0.61698083, -0.8860234], "sigma": [0.2, 0.2]}, {"x": [ 72, 252], "to": [0.82624676, -0.1171322], "sigma": [0.2, 0.2]}, {"x": [ 72, 288], "to": [0.83217277, 0.30132193], "sigma": [0.2, 0.2]}, {"x": [ 72, 324], "to": [0.74893667, 0.80824628], "sigma": [0.2, 0.2]}, {"x": [108,   0], "to": [0.66284547, 0.85288292], "sigma": [0.2, 0.2]}, {"x": [108,  36], "to": [0.59724043, 0.88159718], "sigma": [0.2, 0.2]}, {"x": [108,  72], "to": [0.28727426, 0.20407304], "sigma": [0.2, 0.2]}, {"x": [108, 108], "to": [0.90503697, -0.5979697], "sigma": [0.2, 0.2]}, {"x": [108, 144], "to": [1.05726502, -0.8156704], "sigma": [0.2, 0.2]}, {"x": [108, 180], "to": [0.55263541, -1.1994934], "sigma": [0.2, 0.2]}, {"x": [108, 216], "to": [0.50777742, -0.7713018], "sigma": [0.2, 0.2]}, {"x": [108, 252], "to": [0.60347324, -0.2211189], "sigma": [0.2, 0.2]}, {"x": [108, 288], "to": [1.16101443, -0.1406493], "sigma": [0.2, 0.2]}, {"x": [108, 324], "to": [0.92295182, 0.51506096], "sigma": [0.2, 0.2]}, {"x": [144,   0], "to": [0.80924121, 0.83038461], "sigma": [0.2, 0.2]}, {"x": [144,  36], "to": [0.80043759, 0.57306896], "sigma": [0.2, 0.2]}, {"x": [144,  72], "to": [0.74865899, 0.12507470], "sigma": [0.2, 0.2]}, {"x": [144, 108], "to": [0.54867424, -0.2083665], "sigma": [0.2, 0.2]}, {"x": [144, 144], "to": [0.58431995, -0.7811933], "sigma": [0.2, 0.2]}, {"x": [144, 180], "to": [0.71950969, -0.9713840], "sigma": [0.2, 0.2]}, {"x": [144, 216], "to": [0.52307948, -0.8731280], "sigma": [0.2, 0.2]}, {"x": [144, 252], "to": [0.36976490, -0.3895379], "sigma": [0.2, 0.2]}, {"x": [144, 288], "to": [0.37565453, 0.21778435], "sigma": [0.2, 0.2]}, {"x": [144, 324], "to": [0.45793731, 0.85264234], "sigma": [0.2, 0.2]}, {"x": [180,   0], "to": [-0.0441948, 1.09297816], "sigma": [0.2, 0.2]}, {"x": [180,  36], "to": [-0.2817155, 0.69222421], "sigma": [0.2, 0.2]}, {"x": [180,  72], "to": [0.12103868, 0.25006600], "sigma": [0.2, 0.2]}, {"x": [180, 108], "to": [0.11426250, -0.5415858], "sigma": [0.2, 0.2]}, {"x": [180, 144], "to": [0.10181024, -0.8848316], "sigma": [0.2, 0.2]}, {"x": [180, 180], "to": [-0.1477347, -1.1392833], "sigma": [0.2, 0.2]}, {"x": [180, 216], "to": [0.35044408, -0.9500126], "sigma": [0.2, 0.2]}, {"x": [180, 252], "to": [0.18675249, -0.4131455], "sigma": [0.2, 0.2]}, {"x": [180, 288], "to": [0.24436046, 0.35884024], "sigma": [0.2, 0.2]}, {"x": [180, 324], "to": [0.07432997, 1.02698144], "sigma": [0.2, 0.2]}, {"x": [216,   0], "to": [-0.6591356, 0.94999291], "sigma": [0.2, 0.2]}, {"x": [216,  36], "to": [-0.4494247, 0.69657926], "sigma": [0.2, 0.2]}, {"x": [216,  72], "to": [-0.4270339, 0.15420512], "sigma": [0.2, 0.2]}, {"x": [216, 108], "to": [-0.5964852, -0.4521517], "sigma": [0.2, 0.2]}, {"x": [216, 144], "to": [-0.3799727, -0.9904939], "sigma": [0.2, 0.2]}, {"x": [216, 180], "to": [-0.5694217, -1.0015548], "sigma": [0.2, 0.2]}, {"x": [216, 216], "to": [-0.6918730, -0.5267317], "sigma": [0.2, 0.2]}, {"x": [216, 252], "to": [-0.5838720, -0.4841855], "sigma": [0.2, 0.2]}, {"x": [216, 288], "to": [-0.5693374, -0.0133151], "sigma": [0.2, 0.2]}, {"x": [216, 324], "to": [-0.4903301, 1.03380154], "sigma": [0.2, 0.2]}, {"x": [252,   0], "to": [-1.3293399, 0.71483260], "sigma": [0.2, 0.2]}, {"x": [252,  36], "to": [-1.3110310, 0.72705720], "sigma": [0.2, 0.2]}, {"x": [252,  72], "to": [-1.0671501, 0.24425863], "sigma": [0.2, 0.2]}, {"x": [252, 108], "to": [-0.8844714, -0.2823489], "sigma": [0.2, 0.2]}, {"x": [252, 144], "to": [-0.9533401, -1.1736452], "sigma": [0.2, 0.2]}, {"x": [252, 180], "to": [-0.5345838, -1.2210451], "sigma": [0.2, 0.2]}, {"x": [252, 216], "to": [-1.0862084, -0.7348636], "sigma": [0.2, 0.2]}, {"x": [252, 252], "to": [-0.7549718, -0.1849688], "sigma": [0.2, 0.2]}, {"x": [252, 288], "to": [-1.2390564, 0.54575855], "sigma": [0.2, 0.2]}, {"x": [252, 324], "to": [-1.0288154, 0.84115420], "sigma": [0.2, 0.2]}, {"x": [288,   0], "to": [-0.5410771, 1.10696790], "sigma": [0.2, 0.2]}, {"x": [288,  36], "to": [-0.8322681, 0.44386847], "sigma": [0.2, 0.2]}, {"x": [288,  72], "to": [-0.9040048, 0.00519231], "sigma": [0.2, 0.2]}, {"x": [288, 108], "to": [-0.6676514, -0.4833115], "sigma": [0.2, 0.2]}, {"x": [288, 144], "to": [-1.0580007, -1.2009009], "sigma": [0.2, 0.2]}, {"x": [288, 180], "to": [-0.8102370, -1.2521135], "sigma": [0.2, 0.2]}, {"x": [288, 216], "to": [-1.2759558, -0.7864478], "sigma": [0.2, 0.2]}, {"x": [288, 252], "to": [-0.5628566, 0.13344358], "sigma": [0.2, 0.2]}, {"x": [288, 288], "to": [-0.9149276, 0.22418075], "sigma": [0.2, 0.2]}, {"x": [288, 324], "to": [-0.5648838, 0.75833374], "sigma": [0.2, 0.2]}, {"x": [324,   0], "to": [-0.6311144, 0.83818280], "sigma": [0.2, 0.2]}, {"x": [324,  36], "to": [-0.5527385, 0.84973376], "sigma": [0.2, 0.2]}, {"x": [324,  72], "to": [-0.3039325, -0.2189731], "sigma": [0.2, 0.2]}, {"x": [324, 108], "to": [-0.4498324, 0.07328764], "sigma": [0.2, 0.2]}, {"x": [324, 144], "to": [-0.7415195, -0.6128136], "sigma": [0.2, 0.2]}, {"x": [324, 180], "to": [-0.7918942, -1.2435311], "sigma": [0.2, 0.2]}, {"x": [324, 216], "to": [-0.6853270, -0.5134147], "sigma": [0.2, 0.2]}, {"x": [324, 252], "to": [-0.7581712, -0.7304523], "sigma": [0.2, 0.2]}, {"x": [324, 288], "to": [-0.4803783, 0.12660344], "sigma": [0.2, 0.2]}, {"x": [324, 324], "to": [-0.6815587, 0.82271760], "sigma": [0.2, 0.2]}]}', '"input.krigingWeight"', '{"fcn": "m.kernel.rbf", "fill": {"gamma": 2.0}}'], trials)
                        if not skipThese(pfa):
                            print pfa
                            pfas.append(pfa)

                else:
                    for pfa in pat.generateNormal(considered, fcnName, valueOverrides, nondeterministic):
                        if not skipThese(pfa):
                            print pfa
                            pfas.append(pfa)

    open(outputFileName, "w").write('''{"pfa-version": "%s",
 "pfa-tests": [
%s
 ]}''' % (".".join(map(str, versionToTest)),
             ",\n".join(pfas)))
