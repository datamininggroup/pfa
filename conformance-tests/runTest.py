#!/usr/bin/env python

import json
import base64
import math

# NOTE: Due to limitations in JSON, the following substitutions must be made.
#       (JSON can only store finite numbers and legal Unicode strings.)
# 
#   When expecting a "float" or "double":
#     "inf"   -->  floating-point positive infinity
#     "-inf"  -->  floating-point negative infinity
#     "nan"   -->  floating-point not a number
# 
#   When expecting a "bytes" or "fixed":
#     content must be base64-decoded

def convertIn(x, t):
    if t == "float" or t == "double":
        if x == "inf":
            return float("inf")
        elif x == "-inf":
            return float("-inf")
        elif x == "nan":
            return float("nan")
        else:
            return x

    elif t == "bytes" or (isinstance(t, dict) and t["type"] == "fixed"):
        return base64.b64decode(x)

    elif isinstance(t, dict) and t["type"] == "array":
        if not isinstance(x, list): raise Exception
        return [convertIn(v, t["items"]) for v in x]

    elif isinstance(t, dict) and t["type"] == "map":
        if not isinstance(x, dict): raise Exception
        return dict((k, convertIn(v, t["values"])) for k, v in x.items())

    elif isinstance(t, dict) and t["type"] == "record":
        if not isinstance(x, dict): raise Exception
        return dict((f["name"], convertIn(x[f["name"]], f["type"])) for f in t["fields"])

    elif isinstance(t, list):
        if x is None:
            return x
        else:
            tag, value = x.items()[0]
            for ti in t:
                if isinstance(ti, dict) and ti["type"] in ("record", "enum", "fixed"):
                    name = ti["name"]
                elif isinstance(ti, dict):
                    name = ti["type"]
                elif isinstance(ti, basestring):
                    name = ti
                if tag == name:
                    return {tag: convertIn(value, ti)}

    else:
        return x

def convertOut(x, t, dobase64=True):
    if x is None and t == "null":
        return x

    elif x is True or x is False and t == "boolean":
        return x

    elif isinstance(x, (int, long)) and t in ("int", "long"):
        return x

    elif isinstance(x, (int, long, float)) and t in ("float", "double"):
        if math.isinf(x):
            if x > 0.0:
                return "inf"
            else:
                return "-inf"
        elif math.isnan(x):
            return "nan"
        else:
            return x

    elif isinstance(x, basestring) and t == "string":
        return x

    elif isinstance(x, str) and (t == "bytes" or (isinstance(t, dict) and t["type"] == "fixed")):
        if dobase64:
            return base64.b64encode(x)
        else:
            return x

    elif isinstance(x, list) and isinstance(t, dict) and t["type"] == "array":
        return [convertOut(v, t["items"], dobase64) for v in x]

    elif isinstance(x, dict) and isinstance(t, dict) and t["type"] == "map":
        return dict((k, convertOut(v, t["values"], dobase64)) for k, v in x.items())

    elif isinstance(x, dict) and isinstance(t, dict) and t["type"] == "record" and set(x.keys()) == set(f["name"] for f in t["fields"]):
        return dict((f["name"], convertOut(x[f["name"]], f["type"], dobase64)) for f in t["fields"])

    elif isinstance(t, list):
        if x is None:
            if "null" in t:
                return x
            else:
                raise Exception
        elif isinstance(x, dict) and len(x) == 1:
            tag, value = x.items()[0]
            for ti in t:
                if isinstance(ti, dict) and ti["type"] in ("record", "enum", "fixed"):
                    name = ti["name"]
                elif isinstance(ti, dict):
                    name = ti["type"]
                elif isinstance(ti, basestring):
                    name = ti
                if tag == name:
                    return {tag: convertOut(value, ti, dobase64)}
        else:
            for ti in t:
                try:
                    out = convertOut(x, ti, dobase64)
                except:
                    pass
                else:
                    if isinstance(ti, dict) and ti["type"] in ("record", "enum", "fixed"):
                        if "namespace" in ti:
                            name = ti["namespace"] + "." + ti["name"]
                        else:
                            name = ti["name"]
                    elif isinstance(ti, dict):
                        name = ti["type"]
                    elif ti in ("boolean", "int", "long", "float", "double", "string", "bytes"):
                        name = ti
                    return {name: out}
            raise Exception

    else:
        raise Exception

def checkInputType(x, t, typeNames):
    if t == "null":
        if x is not None:
            raise TypeError("Input incorrectly prepared: " + repr(x) + " " + json.dumps(t))
    elif t == "boolean":
        if x is not True and x is not False:
            raise TypeError("Input incorrectly prepared: " + repr(x) + " " + json.dumps(t))
    elif t == "int" or t == "long":
        if not isinstance(x, (int, long)):
            raise TypeError("Input incorrectly prepared: " + repr(x) + " " + json.dumps(t))
    elif t == "float" or t == "double":
        if not isinstance(x, (int, long, float)):
            raise TypeError("Input incorrectly prepared: " + repr(x) + " " + json.dumps(t))
    elif t == "string":
        if not isinstance(x, unicode):
            raise TypeError("Input incorrectly prepared: " + repr(x) + " " + json.dumps(t))
    elif t == "bytes":
        if not isinstance(x, str):
            raise TypeError("Input incorrectly prepared: " + repr(x) + " " + json.dumps(t))
    elif isinstance(t, basestring):
        t = typeNames[t]
    if isinstance(t, dict) and t["type"] == "array":
        if not isinstance(x, list):
            raise TypeError("Input incorrectly prepared: " + repr(x) + " " + json.dumps(t))
        for v in x:
            checkInputType(v, t["items"], typeNames)
    elif isinstance(t, dict) and t["type"] == "map":
        if not isinstance(x, dict):
            raise TypeError("Input incorrectly prepared: " + repr(x) + " " + json.dumps(t))
        for k, v in x.items():
            checkInputType(v, t["values"], typeNames)
    elif isinstance(t, dict) and t["type"] == "record":
        if not isinstance(x, dict) or set(x.keys()) != set(f["name"] for f in t["fields"]):
            raise TypeError("Input incorrectly prepared: " + repr(x) + " " + json.dumps(t))
        for f in t["fields"]:
            checkInputType(x[f["name"]], f["type"], typeNames)
    elif isinstance(t, dict) and t["type"] == "fixed":
        if not isinstance(x, str):
            raise TypeError("Input incorrectly prepared: " + repr(x) + " " + json.dumps(t))
    elif isinstance(t, dict) and t["type"] == "enum":
        if not isinstance(x, unicode):
            raise TypeError("Input incorrectly prepared: " + repr(x) + " " + json.dumps(t))
    elif isinstance(t, list):
        if x is None:
            if "null" not in t:
                raise TypeError("Input incorrectly prepared: " + repr(x) + " " + json.dumps(t))
        elif isinstance(x, dict) and len(x) == 1:
            tag, value = x.items()[0]
            found = False
            for ti in t:
                if isinstance(ti, dict) and ti["type"] in ("record", "enum", "fixed"):
                    name = ti["name"]
                elif isinstance(ti, dict):
                    name = ti["type"]
                elif isinstance(ti, basestring):
                    name = ti
                if tag == name:
                    found = True
                    checkInputType(value, ti, typeNames)
            if not found:
                raise TypeError("Input incorrectly prepared: " + repr(x) + " " + json.dumps(t))
        else:
            raise TypeError("Input incorrectly prepared: " + repr(x) + " " + json.dumps(t))
    elif not isinstance(t, basestring):
        raise TypeError("Input incorrectly prepared: " + repr(x) + " " + json.dumps(t))
    return x

def getNamesFromType(t):
    if isinstance(t, dict) and t["type"] == "array":
        return getNamesFromType(t["items"])
    elif isinstance(t, dict) and t["type"] == "map":
        return getNamesFromType(t["values"])
    elif isinstance(t, dict) and t["type"] == "record":
        out = {t["name"]: t}
        for f in t["fields"]:
            out.update(getNamesFromType(f["type"]))
        return out
    elif isinstance(t, dict) and t["type"] == "fixed":
        return {t["name"]: t}
    elif isinstance(t, dict) and t["type"] == "enum":
        return {t["name"]: t}
    elif isinstance(t, list):
        out = {}
        for ti in t:
            out.update(getNamesFromType(ti))
        return out
    else:
        return {}

def getNamesFromFunctions(fcns):
    out = {}
    for fcn in fcns:
        for param in fcn["params"]:
            out.update(getNamesFromType(param.values()[0]))
        out.update(getNamesFromType(fcn["ret"]))
    return out

def convertInput(example):
    inputType = example["engine"]["input"]
    typeNames = getNamesFromFunctions([x for x in example["engine"]["action"][example["function"]] if isinstance(x, dict) and "params" in x])
    typeNames.update(getNamesFromType(inputType))
    try:
        trials = [dict(x, sample=checkInputType(convertIn(x["sample"], inputType), inputType, typeNames)) for x in example["trials"]]
    except TypeError:
        print example["function"] + "\t" + json.dumps(example["engine"])
        raise
    return dict(example, trials=trials)

def getExamples(openFile):
    # take advantage of the formatting of the file to find breaks between examples
    inFunction = False
    collectedString = []
    for line in openFile:
        if line.startswith("""     {"function":"""):
            inFunction = True
        elif line == """     },\n""" or line == """     }\n""":
            inFunction = False
            collectedString.append("}")
            yield convertInput(json.loads("".join(collectedString)))
            collectedString = []
        if inFunction:
            collectedString.append(line)

def compare(one, two, zeroTolerance, fractionalTolerance, infinityTolerance, breadcrumbs=None):
    if breadcrumbs is None:
        breadcrumbs = ["top"]
    if isinstance(one, dict) and isinstance(two, dict):
        if set(one.keys()) != set(two.keys()):
            yield "different dict keys: {%s} vs {%s} at %s" % (", ".join(sorted(one.keys())), ", ".join(sorted(two.keys())), " -> ".join(breadcrumbs))
        else:
            for k in sorted(one.keys()):
                for x in compare(one[k], two[k], zeroTolerance, fractionalTolerance, infinityTolerance, breadcrumbs + [k]):
                    yield x
    elif isinstance(one, list) and isinstance(two, list):
        if len(one) != len(two):
            yield "different list lengths: %d vs %d at %s" % (len(one), len(two), " -> ".join(breadcrumbs))
        else:
            for i in xrange(len(one)):
                for x in compare(one[i], two[i], zeroTolerance, fractionalTolerance, infinityTolerance, breadcrumbs + [str(i)]):
                    yield x
    elif isinstance(one, basestring) and isinstance(two, basestring):
        if one != two:
            yield "different values: %s vs %s at %s" % (json.dumps(one), json.dumps(two), " -> ".join(breadcrumbs))
    elif isinstance(one, bool) and isinstance(two, bool):
        if one != two:
            yield "different values: %r vs %r at %s" % (one, two, " -> ".join(breadcrumbs))
    elif isinstance(one, (int, long)) and isinstance(two, (int, long)):
        if one != two:
            yield "different values: %d vs %d at %s" % (one, two, " -> ".join(breadcrumbs))
    elif one == "inf" and isinstance(two, (int, long, float)) and two > infinityTolerance:
        pass
    elif one == "-inf" and isinstance(two, (int, long, float)) and two < -infinityTolerance:
        pass
    elif two == "inf" and isinstance(one, (int, long, float)) and one > infinityTolerance:
        pass
    elif two == "-inf" and isinstance(one, (int, long, float)) and one < -infinityTolerance:
        pass
    elif (one == "inf" or one == "-inf" or one == "nan") and isinstance(two, (int, long, float)):
        yield "different values: %s vs %g at %s" % (one, two, " -> ".join(breadcrumbs))
    elif (two == "inf" or two == "-inf" or two == "nan") and isinstance(one, (int, long, float)):
        yield "different values: %g vs %s at %s" % (one, two, " -> ".join(breadcrumbs))
    elif isinstance(one, (int, long, float)) and isinstance(two, (int, long, float)):
        if abs(one) < zeroTolerance and abs(two) < zeroTolerance:
            pass   # they're both about zero
        elif abs(one) < zeroTolerance:
            yield "different values beyond tolerance: %g ~ 0 vs %g at %s" % (one, two, " -> ".join(breadcrumbs))
        elif abs(two) < zeroTolerance:
            yield "different values beyond tolerance: %g vs %g ~ 0 at %s" % (one, two, " -> ".join(breadcrumbs))
        elif abs(one - two)/abs(one) > fractionalTolerance:
            yield "different values beyond tolerance: abs(%g - %g)/%g = %g at %s" % (one, two, abs(one), abs(one - two)/abs(one), " -> ".join(breadcrumbs))
    elif isinstance(one, bool) and isinstance(two, bool):
        if one != two:
            yield "different values: %r vs %r at %s" % (one, two, " -> ".join(breadcrumbs))
    elif one is None and two is None:
        pass
    else:
        yield "different types: %s vs %s at %s" % (type(one).__name__, type(two).__name__, " -> ".join(breadcrumbs))

if __name__ == "__main__":
    for example in getExamples(open("pfa-tests.json")):
        print json.dumps(example["engine"])
