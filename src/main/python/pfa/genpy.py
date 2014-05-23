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

    def __call__(self, context):
        if isinstance(context, EngineConfig.Context):
            return self.doEngineConfig(context)
        elif isinstance(context, Cell.Context):
            return self.doCell(context)
        elif isinstance(context, Pool.Context):
            return self.doPool(context)
        elif isinstance(context, FcnDef.Context):
            return self.doFcnDef(context)
        elif isinstance(context, FcnRef.Context):
            return self.doFcnRef(context)
        elif isinstance(context, Call.Context):
            return self.doCall(context)
        elif isinstance(context, Ref.Context):
            return self.doRef(context)
        elif isinstance(context, LiteralNull.Context):
            return self.doLiteralNull(context)
        elif isinstance(context, LiteralBoolean.Context):
            return self.doLiteralBoolean(context)
        elif isinstance(context, LiteralInt.Context):
            return self.doLiteralInt(context)
        elif isinstance(context, LiteralLong.Context):
            return self.doLiteralLong(context)
        elif isinstance(context, LiteralFloat.Context):
            return self.doLiteralFloat(context)
        elif isinstance(context, LiteralDouble.Context):
            return self.doLiteralDouble(context)
        elif isinstance(context, LiteralString.Context):
            return self.doLiteralString(context)
        elif isinstance(context, LiteralBase64.Context):
            return self.doLiteralBase64(context)
        elif isinstance(context, Literal.Context):
            return self.doLiteral(context)
        elif isinstance(context, NewObject.Context):
            return self.doNewObject(context)
        elif isinstance(context, NewArray.Context):
            return self.doNewArray(context)
        elif isinstance(context, Do.Context):
            return self.doDo(context)
        elif isinstance(context, Let.Context):
            return self.doLet(context)
        elif isinstance(context, SetVar.Context):
            return self.doSetVar(context)
        elif isinstance(context, AttrGet.Context):
            return self.doAttrGet(context)
        elif isinstance(context, AttrTo.Context):
            return self.doAttrTo(context)
        elif isinstance(context, CellGet.Context):
            return self.doCellGet(context)
        elif isinstance(context, CellTo.Context):
            return self.doCellTo(context)
        elif isinstance(context, PoolGet.Context):
            return self.doPoolGet(context)
        elif isinstance(context, PoolTo.Context):
            return self.doPoolTo(context)
        elif isinstance(context, If.Context):
            return self.doIf(context)
        elif isinstance(context, Cond.Context):
            return self.doCond(context)
        elif isinstance(context, While.Context):
            return self.doWhile(context)
        elif isinstance(context, DoUntil.Context):
            return self.doDoUntil(context)
        elif isinstance(context, For.Context):
            return self.doFor(context)
        elif isinstance(context, Foreach.Context):
            return self.doForeach(context)
        elif isinstance(context, Forkeyval.Context):
            return self.doForkeyval(context)
        elif isinstance(context, CastCase.Context):
            return self.doCastCase(context)
        elif isinstance(context, CastBlock.Context):
            return self.doCastBlock(context)
        elif isinstance(context, Upcast.Context):
            return self.doUpcast(context)
        elif isinstance(context, IfNotNull.Context):
            return self.doIfNotNull(context)
        elif isinstance(context, Doc.Context):
            return self.doDoc(context)
        elif isinstance(context, Error.Context):
            return self.doError(context)
        elif isinstance(context, Log.Context):
            return self.doLog(context)
        else:
            raise PFASemanticException("unrecognized context class: " + str(type(context)), "")

    def returnLast(self, codes, indent):
        return "".join(indent + x + "\n" for x in codes[:-1]) + indent + "return " + codes[-1] + "\n"

    def returnNone(self, codes, indent):
        return "".join(indent + x + "\n" for x in codes)

    def doEngineConfig(self, context):
        if context.name is None:
            name = pfa.util.uniqueEngineName()
        else:
            name = context.name
        
        return """
class PFA_{name}(PFAEngine):
    def __init__(self):
        pass

    def action(self, input):
        scope = DynamicScope(None)
        scope.let("input", input)
{action}

PFA_{name}.functionTable = functionTable
""".format(name=name, action=self.returnLast(context.action, "        "))
   
    def doCell(self, context):
        raise NotImplementedError("doCell")
    
    def doPool(self, context):
        raise NotImplementedError("doPool")
    
    def doFcnDef(self, context):
        raise NotImplementedError("doFcnDef")
    
    def doFcnRef(self, context):
        raise NotImplementedError("doFcnRef")
    
    def doCall(self, context):
        return context.fcn.genpy(context.paramTypes, context.args)
    
    def doRef(self, context):
        return "scope.get({})".format(repr(context.name))
    
    def doLiteralNull(self, context):
        return "None"
    
    def doLiteralBoolean(self, context):
        return str(context.value)
    
    def doLiteralInt(self, context):
        return str(context.value)
    
    def doLiteralLong(self, context):
        return str(context.value)
    
    def doLiteralFloat(self, context):
        return str(float(context.value))
    
    def doLiteralDouble(self, context):
        return str(float(context.value))
    
    def doLiteralString(self, context):
        return repr(context.value)
    
    def doLiteralBase64(self, context):
        try:
            data = base64.decode(context.value)
        except Exception as err:
            raise PFASemanticException("error interpreting base64: " + str(err))
        else:
            return repr(data)
    
    def doLiteral(self, context):
        raise NotImplementedError("doLiteral")
    
    def doNewObject(self, context):
        raise NotImplementedError("doNewObject")
    
    def doNewArray(self, context):
        raise NotImplementedError("doNewArray")
    
    def doDo(self, context):
        raise NotImplementedError("doDo")
    
    def doLet(self, context):
        raise NotImplementedError("doLet")
    
    def doSetVar(self, context):
        raise NotImplementedError("doSetVar")
    
    def doAttrGet(self, context):
        raise NotImplementedError("doAttrGet")
    
    def doAttrTo(self, context):
        raise NotImplementedError("doAttrTo")
    
    def doCellGet(self, context):
        raise NotImplementedError("doCellGet")
    
    def doCellTo(self, context):
        raise NotImplementedError("doCellTo")
    
    def doPoolGet(self, context):
        raise NotImplementedError("doPoolGet")
    
    def doPoolTo(self, context):
        raise NotImplementedError("doPoolTo")
    
    def doIf(self, context):
        raise NotImplementedError("doIf")
    
    def doCond(self, context):
        raise NotImplementedError("doCond")
    
    def doWhile(self, context):
        raise NotImplementedError("doWhile")
    
    def doDoUntil(self, context):
        raise NotImplementedError("doDoUntil")
    
    def doFor(self, context):
        raise NotImplementedError("doFor")
    
    def doForeach(self, context):
        raise NotImplementedError("doForeach")
    
    def doForkeyval(self, context):
        raise NotImplementedError("doForkeyval")
    
    def doCastCase(self, context):
        raise NotImplementedError("doCastCase")
    
    def doCastBlock(self, context):
        raise NotImplementedError("doCastBlock")
    
    def doUpcast(self, context):
        raise NotImplementedError("doUpcast")
    
    def doIfNotNull(self, context):
        raise NotImplementedError("doIfNotNull")
    
    def doDoc(self, context):
        raise NotImplementedError("doDoc")
    
    def doError(self, context):
        raise NotImplementedError("doError")
    
    def doLog(self, context):
        raise NotImplementedError("doLog")

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

    def let(self, symbol, init):
        self.symbols[symbol] = init

    def set(self, symbol, value):
        if symbol in self.symbols:
            self.symbols[symbol] = value
        elif self.parent is not None:
            self.parent.set(symbol, value)
        else:
            raise RuntimeError()

class PFAEngine(object):
    @staticmethod
    def fromAst(engineConfig, options=None, sharedState=None, multiplicity=1, style="pure", debug=False):
        functionTable = pfa.ast.FunctionTable.blank()
        context, code = engineConfig.walk(GeneratePython.makeTask(style), pfa.ast.SymbolTable.blank(), functionTable)
        if debug:
            print code

        local = {"PFAEngine": PFAEngine, "DynamicScope": DynamicScope, "functionTable": functionTable, "math": math}

        exec(code, globals(), local)
        cls = [x for x in local.values() if getattr(x, "__bases__", None) == (PFAEngine,)][0]

        return [cls() for x in xrange(multiplicity)]

    @staticmethod
    def fromJson(src, options=None, sharedState=None, multiplicity=1, style="pure", debug=False):
        return PFAEngine.fromAst(pfa.reader.jsonToAst(src), options, sharedState, multiplicity, style, debug)

    @staticmethod
    def fromYaml(src, options=None, sharedState=None, multiplicity=1, style="pure", debug=False):
        return PFAEngine.fromAst(pfa.reader.yamlToAst(src), options, sharedState, multiplicity, style, debug)
