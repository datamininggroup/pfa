#!/usr/bin/env python

import inspect
import sys

uniqueEngineNameCounter = 0
def uniqueEngineName():
    sys.modules["pfa.util"].uniqueEngineNameCounter += 1
    return "Engine_{}".format(sys.modules["pfa.util"].uniqueEngineNameCounter)

uniqueRecordNameCounter = 0
def uniqueRecordName():
    sys.modules["pfa.util"].uniqueRecordNameCounter += 1
    return "Record_{}".format(sys.modules["pfa.util"].uniqueRecordNameCounter)

uniqueEnumNameCounter = 0
def uniqueEnumName():
    sys.modules["pfa.util"].uniqueEnumNameCounter += 1
    return "Enum_{}".format(sys.modules["pfa.util"].uniqueEnumNameCounter)

uniqueFixedNameCounter = 0
def uniqueFixedName():
    sys.modules["pfa.util"].uniqueFixedNameCounter += 1
    return "Fixed_{}".format(sys.modules["pfa.util"].uniqueFixedNameCounter)

def pos(dot, at):
    return "in{} object from {}".format("" if (dot == "") else " field " + dot + " of", at)

def flatten(x):
    return [item for sublist in x for item in sublist]

def case(clazz):
    fields = [x for x in inspect.getargspec(clazz.__init__).args[1:] if x != "pos"]

    try:
        code = clazz.__init__.__func__
    except AttributeError:
        code = clazz.__init__.func_code

    context = dict(globals())
    context[clazz.__name__] = clazz

    if "pos" in inspect.getargspec(clazz.__init__).args:
        argFields = fields + ["pos=None"]
        assignFields = fields + ["pos"]
    else:
        argFields = assignFields = fields

    newMethods = {}
    exec("""
def __init__(self, {args}):
{assign}
    self._init({args})
""".format(args=", ".join(argFields),
           assign="\n".join(["    self.{0} = {0}".format(x) for x in (assignFields)])),
         context,
         newMethods)
    
    if len(fields) == 0:
        exec("""
def __repr__(self):
    return \"{}()\"
""".format(clazz.__name__), context, newMethods)

        exec("""
def __eq__(self, other):
    return isinstance(other, {})
""".format(clazz.__name__), context, newMethods)

    else:
        exec("""
def __repr__(self):
    return \"{}(\" + {} + \")\"
""".format(clazz.__name__, "+ \", \" + ".join(["repr(self." + x + ")" for x in fields])),
             context,
             newMethods)

        exec("""
def __eq__(self, other):
    if isinstance(other, {}):
        return {}
    else:
        return False
""".format(clazz.__name__, " and ".join(["self.{x} == other.{x}".format(x=x) for x in fields])),
             context,
             newMethods)

    clazz._init = clazz.__init__
    clazz.__init__ = newMethods["__init__"]

    if hasattr(clazz, "toString"):
        clazz.__repr__ = clazz.toString
    else:
        clazz.__repr__ = newMethods["__repr__"]

    if hasattr(clazz, "equals"):
        clazz.__eq__ = clazz.equals
    else:
        clazz.__eq__ = newMethods["__eq__"]

    return clazz

