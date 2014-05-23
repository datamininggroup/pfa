#!/usr/bin/env python

import math
import base64

import pfa.ast
import pfa.util
import pfa.reader
from pfa.errors import PFASemanticException

from pfa.ast import EngineConfig
from pfa.ast import Cell
from pfa.ast import Pool
from pfa.ast import FcnDef
from pfa.ast import FcnRef
from pfa.ast import Call
from pfa.ast import Ref
from pfa.ast import LiteralNull
from pfa.ast import LiteralBoolean
from pfa.ast import LiteralInt
from pfa.ast import LiteralLong
from pfa.ast import LiteralFloat
from pfa.ast import LiteralDouble
from pfa.ast import LiteralString
from pfa.ast import LiteralBase64
from pfa.ast import Literal
from pfa.ast import NewObject
from pfa.ast import NewArray
from pfa.ast import Do
from pfa.ast import Let
from pfa.ast import SetVar
from pfa.ast import AttrGet
from pfa.ast import AttrTo
from pfa.ast import CellGet
from pfa.ast import CellTo
from pfa.ast import PoolGet
from pfa.ast import PoolTo
from pfa.ast import If
from pfa.ast import Cond
from pfa.ast import While
from pfa.ast import DoUntil
from pfa.ast import For
from pfa.ast import Foreach
from pfa.ast import Forkeyval
from pfa.ast import CastCase
from pfa.ast import CastBlock
from pfa.ast import Upcast
from pfa.ast import IfNotNull
from pfa.ast import Doc
from pfa.ast import Error
from pfa.ast import Log

class GeneratePython(pfa.ast.Task):
    @staticmethod
    def makeTask(style):
        if style == "pure":
            return GeneratePythonPure()
        else:
            raise NotImplementedException("unrecognized style " + style)

    def returnLast(self, codes, indent):
        return "".join(indent + x + "\n" for x in codes[:-1]) + indent + "return " + codes[-1] + "\n"

    def returnNone(self, codes, indent):
        return "".join(indent + x + "\n" for x in codes)

    def __call__(self, context):
        if isinstance(context, EngineConfig.Context):
            if context.name is None:
                name = pfa.util.uniqueEngineName()
            else:
                name = context.name

            return """class PFA_{name}(PFAEngine):
    def __init__(self):
        pass

    def action(self, input):
        scope = DynamicScope(None)
        scope.let({{'input': input}})
{action}

PFA_{name}.functionTable = functionTable
""".format(name=name, action=self.returnLast(context.action, "        "))

        elif isinstance(context, Cell.Context):
            raise NotImplementedError("Cell")

        elif isinstance(context, Pool.Context):
            raise NotImplementedError("Pool")

        elif isinstance(context, FcnDef.Context):
            raise NotImplementedError("FcnDef")

        elif isinstance(context, FcnRef.Context):
            raise NotImplementedError("FcnRef")

        elif isinstance(context, Call.Context):
            return context.fcn.genpy(context.paramTypes, context.args)

        elif isinstance(context, Ref.Context):
            return "scope.get({})".format(repr(context.name))

        elif isinstance(context, LiteralNull.Context):
            return "None"

        elif isinstance(context, LiteralBoolean.Context):
            return str(context.value)

        elif isinstance(context, LiteralInt.Context):
            return str(context.value)

        elif isinstance(context, LiteralLong.Context):
            return str(context.value)

        elif isinstance(context, LiteralFloat.Context):
            return str(float(context.value))

        elif isinstance(context, LiteralDouble.Context):
            return str(float(context.value))

        elif isinstance(context, LiteralString.Context):
            return repr(context.value)

        elif isinstance(context, LiteralBase64.Context):
            try:
                data = base64.decode(context.value)
            except Exception as err:
                raise PFASemanticException("error interpreting base64: " + str(err))
            else:
                return repr(data)

        elif isinstance(context, Literal.Context):
            raise NotImplementedError("Literal")

        elif isinstance(context, NewObject.Context):
            raise NotImplementedError("NewObject")

        elif isinstance(context, NewArray.Context):
            raise NotImplementedError("NewArray")

        elif isinstance(context, Do.Context):
            raise NotImplementedError("Do")

        elif isinstance(context, Let.Context):
            return "scope.let({" + ", ".join(repr(n) + ": " + e for n, t, e in context.nameTypeExpr) + "})"

        elif isinstance(context, SetVar.Context):
            return "scope.set({" + ", ".join(repr(n) + ": " + e for n, t, e in context.nameTypeExpr) + "})"

        elif isinstance(context, AttrGet.Context):
            raise NotImplementedError("AttrGet")

        elif isinstance(context, AttrTo.Context):
            raise NotImplementedError("AttrTo")

        elif isinstance(context, CellGet.Context):
            raise NotImplementedError("CellGet")

        elif isinstance(context, CellTo.Context):
            raise NotImplementedError("CellTo")

        elif isinstance(context, PoolGet.Context):
            raise NotImplementedError("PoolGet")

        elif isinstance(context, PoolTo.Context):
            raise NotImplementedError("PoolTo")

        elif isinstance(context, If.Context):
            if context.elseClause is None:
                return "ifThen(scope, lambda scope: {}, lambda scope: do({}))".format(context.predicate, ", ".join(context.thenClause))
            else:
                return "ifThenElse(scope, lambda scope: {}, lambda scope: do({}), lambda scope: do({}))".format(context.predicate, ", ".join(context.thenClause), ", ".join(context.elseClause))

        elif isinstance(context, Cond.Context):
            if not context.complete:
                return "cond(scope, [{}])".format(", ".join("(lambda scope: {}, lambda scope: do({}))".format(walkBlock.pred, ", ".join(walkBlock.exprs)) for walkBlock in context.walkBlocks))
            else:
                return "condElse(scope, [{}], lambda scope: do({}))".format(", ".join("(lambda scope: {}, lambda scope: do({}))".format(walkBlock.pred, ", ".join(walkBlock.exprs)) for walkBlock in context.walkBlocks[:-1]), ", ".join(context.walkBlocks[-1].exprs))

        elif isinstance(context, While.Context):
            raise NotImplementedError("While")

        elif isinstance(context, DoUntil.Context):
            raise NotImplementedError("DoUntil")

        elif isinstance(context, For.Context):
            raise NotImplementedError("For")

        elif isinstance(context, Foreach.Context):
            raise NotImplementedError("Foreach")

        elif isinstance(context, Forkeyval.Context):
            raise NotImplementedError("Forkeyval")

        elif isinstance(context, CastCase.Context):
            raise NotImplementedError("CastCase")

        elif isinstance(context, CastBlock.Context):
            raise NotImplementedError("CastBlock")

        elif isinstance(context, Upcast.Context):
            raise NotImplementedError("Upcast")

        elif isinstance(context, IfNotNull.Context):
            raise NotImplementedError("IfNotNull")

        elif isinstance(context, Doc.Context):
            raise NotImplementedError("Doc")

        elif isinstance(context, Error.Context):
            raise NotImplementedError("Error")

        elif isinstance(context, Log.Context):
            raise NotImplementedError("Log")

        else:
            raise PFASemanticException("unrecognized context class: " + str(type(context)), "")

class GeneratePythonPure(GeneratePython):
    pass

###########################################################################

class DynamicScope(object):
    def __init__(self, parent):
        self.parent = parent
        self.symbols = dict()

    def get(self, symbol):
        if symbol in self.symbols:
            return self.symbols[symbol]
        elif self.parent is not None:
            return self.parent.get(symbol)
        else:
            raise RuntimeError()

    def let(self, nameExpr):
        for symbol, init in nameExpr.items():
            self.symbols[symbol] = init

    def set(self, nameExpr):
        for symbol, value in nameExpr.items():
            if symbol in self.symbols:
                self.symbols[symbol] = value
            elif self.parent is not None:
                self.parent.set(nameExpr)
            else:
                raise RuntimeError()

def do(*exprs):
    if len(exprs) > 0:
        return exprs[-1]
    else:
        return None

def ifThen(scope, predicate, thenClause):
    if predicate(DynamicScope(scope)):
        thenClause(DynamicScope(scope))
    return None

def ifThenElse(scope, predicate, thenClause, elseClause):
    if predicate(DynamicScope(scope)):
        return thenClause(DynamicScope(scope))
    else:
        return elseClause(DynamicScope(scope))

def cond(scope, ifThens):
    for predicate, thenClause in ifThens:
        if predicate(DynamicScope(scope)):
            thenClause(DynamicScope(scope))
            break
    return None

def condElse(scope, ifThens, elseClause):
    for predicate, thenClause in ifThens:
        if predicate(DynamicScope(scope)):
            return thenClause(DynamicScope(scope))
    return elseClause(DynamicScope(scope))
    
class PFAEngine(object):
    @staticmethod
    def fromAst(engineConfig, options=None, sharedState=None, multiplicity=1, style="pure", debug=False):
        functionTable = pfa.ast.FunctionTable.blank()
        context, code = engineConfig.walk(GeneratePython.makeTask(style), pfa.ast.SymbolTable.blank(), functionTable)
        if debug:
            print code

        sandbox = {"PFAEngine": PFAEngine,
                   "DynamicScope": DynamicScope,
                   "functionTable": functionTable,
                   "do": do,
                   "ifThen": ifThen,
                   "ifThenElse": ifThenElse,
                   "cond": cond,
                   "condElse": condElse,
                   "math": math,
                   }

        exec(code, sandbox)
        cls = [x for x in sandbox.values() if getattr(x, "__bases__", None) == (PFAEngine,)][0]

        return [cls() for x in xrange(multiplicity)]

    @staticmethod
    def fromJson(src, options=None, sharedState=None, multiplicity=1, style="pure", debug=False):
        return PFAEngine.fromAst(pfa.reader.jsonToAst(src), options, sharedState, multiplicity, style, debug)

    @staticmethod
    def fromYaml(src, options=None, sharedState=None, multiplicity=1, style="pure", debug=False):
        return PFAEngine.fromAst(pfa.reader.yamlToAst(src), options, sharedState, multiplicity, style, debug)
