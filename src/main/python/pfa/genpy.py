#!/usr/bin/env python

import math
import base64
import time
import json

import pfa.ast
import pfa.util
import pfa.reader
import pfa.datatype
import options
from pfa.errors import *

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

from pfa.ast import ArrayIndex
from pfa.ast import MapIndex
from pfa.ast import RecordIndex

class GeneratePython(pfa.ast.Task):
    @staticmethod
    def makeTask(style):
        if style == "pure":
            return GeneratePythonPure()
        else:
            raise NotImplementedError("unrecognized style " + style)

    def returnLast(self, codes, indent):
        return "".join(indent + x + "\n" for x in codes[:-1]) + indent + "return " + codes[-1] + "\n"

    def returnNone(self, codes, indent):
        return "".join(indent + x + "\n" for x in codes)

    def expandPath(self, path):
        out = []
        for p in path:
            if isinstance(p, ArrayIndex):
                out.append("[" + p.i + "]")
            elif isinstance(p, MapIndex):
                out.append("[" + p.k + "]")
            elif isinstance(p, RecordIndex):
                out.append("[" + repr(p.f) + "]")
            else:
                raise Exception
        return "".join(out)

    def reprPath(self, path):
        out = []
        for p in path:
            if isinstance(p, ArrayIndex):
                out.append(p.i)
            elif isinstance(p, MapIndex):
                out.append(p.k)
            elif isinstance(p, RecordIndex):
                out.append(repr(p.f))
            else:
                raise Exception
        return ", ".join(out)

    def __call__(self, context):
        if isinstance(context, EngineConfig.Context):
            if context.name is None:
                name = pfa.util.uniqueEngineName()
            else:
                name = context.name

            out = ["class PFA_" + name + """(PFAEngine):
    def __init__(self, functionTable, cells, pools, options, logger):
        self.f = functionTable.functions
        self.cells = cells
        self.pools = pools
        self.options = options
        self.logger = logger
"""]

            for ufname, fcnContext in context.fcns:
                out.append("        self.f[" + repr(ufname) + "] = " + self(fcnContext))

            out.append("""
    def action(self, input):
        state = ExecutionState(self.options, 'action')
        scope = DynamicScope(None)
        scope.let({'input': input})
""" + self.returnLast(context.action, "        "))

            return "".join(out)

        elif isinstance(context, FcnDef.Context):
            return "lambda state, scope: do(" + ", ".join(context.exprs) + ")"

        elif isinstance(context, FcnRef.Context):
            return "self.f[" + repr(context.fcn.name) + "]"

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
            return repr(pfa.datatype.jsonDecoder(context.retType, json.loads(context.value)))

        elif isinstance(context, NewObject.Context):
            return "{" + ", ".join(repr(k) + ": " + v for k, v in context.fields.items()) + "}"

        elif isinstance(context, NewArray.Context):
            return "[" + ", ".join(context.items) + "]"

        elif isinstance(context, Do.Context):
            return "do(" + ", ".join(context.exprs) + ")"

        elif isinstance(context, Let.Context):
            return "scope.let({" + ", ".join(repr(n) + ": " + e for n, t, e in context.nameTypeExpr) + "})"

        elif isinstance(context, SetVar.Context):
            return "scope.set({" + ", ".join(repr(n) + ": " + e for n, t, e in context.nameTypeExpr) + "})"

        elif isinstance(context, AttrGet.Context):
            return context.expr + self.expandPath(context.path)

        elif isinstance(context, AttrTo.Context):
            return "update({}, [{}], {})".format(context.expr, self.reprPath(context.path), context.to)

        elif isinstance(context, CellGet.Context):
            return "self.cells[" + repr(context.cell) + "]" + self.expandPath(context.path)

        elif isinstance(context, CellTo.Context):
            return "self.cells[{}].update([{}], {})".format(repr(context.cell), self.reprPath(context.path), context.to)

        elif isinstance(context, PoolGet.Context):
            return "self.pools[" + repr(context.pool) + "]" + self.expandPath(context.path)

        elif isinstance(context, PoolTo.Context):
            return "self.pools[{}].update([{}], {}, {})".format(repr(context.pool), self.reprPath(context.path), context.to, context.init)

        elif isinstance(context, If.Context):
            if context.elseClause is None:
                return "ifThen(state, scope, lambda state, scope: {}, lambda state, scope: do({}))".format(context.predicate, ", ".join(context.thenClause))
            else:
                return "ifThenElse(state, scope, lambda state, scope: {}, lambda state, scope: do({}), lambda state, scope: do({}))".format(context.predicate, ", ".join(context.thenClause), ", ".join(context.elseClause))

        elif isinstance(context, Cond.Context):
            if not context.complete:
                return "cond(state, scope, [{}])".format(", ".join("(lambda state, scope: {}, lambda state, scope: do({}))".format(walkBlock.pred, ", ".join(walkBlock.exprs)) for walkBlock in context.walkBlocks))
            else:
                return "condElse(state, scope, [{}], lambda state, scope: do({}))".format(", ".join("(lambda state, scope: {}, lambda state, scope: do({}))".format(walkBlock.pred, ", ".join(walkBlock.exprs)) for walkBlock in context.walkBlocks[:-1]), ", ".join(context.walkBlocks[-1].exprs))

        elif isinstance(context, While.Context):
            return "doWhile(state, scope, lambda state, scope: {}, lambda state, scope: do({}))".format(context.predicate, ", ".join(context.loopBody))

        elif isinstance(context, DoUntil.Context):
            return "doUntil(state, scope, lambda state, scope: {}, lambda state, scope: do({}))".format(context.predicate, ", ".join(context.loopBody))

        elif isinstance(context, For.Context):
            return "doFor(state, scope, lambda state, scope: scope.let({" + ", ".join(repr(n) + ": " + e for n, t, e in context.initNameTypeExpr) + "}), lambda state, scope: " + context.predicate + ", lambda state, scope: scope.set({" + ", ".join(repr(n) + ": " + e for n, t, e in context.stepNameTypeExpr) + "}), lambda state, scope: do(" + ", ".join(context.loopBody) + "))"

        elif isinstance(context, Foreach.Context):
            return "doForeach(state, scope, {}, {}, lambda state, scope: do({}))".format(repr(context.name), context.objExpr, ", ".join(context.loopBody))

        elif isinstance(context, Forkeyval.Context):
            return "doForkeyval(state, scope, {}, {}, {}, lambda state, scope: do({}))".format(repr(context.forkey), repr(context.forval), context.objExpr, ", ".join(context.loopBody))

        elif isinstance(context, CastCase.Context):
            return "(" + repr(context.name) + ", " + repr(context.toType) + ", lambda state, scope: do(" + ", ".join(context.clause) + "))"

        elif isinstance(context, CastBlock.Context):
            return "cast(state, scope, " + context.expr + ", " + repr(context.exprType) + ", [" + ", ".join(caseRes for castCtx, caseRes in context.cases) + "], " + repr(context.partial) + ", self.parser)"

        elif isinstance(context, Upcast.Context):
            return context.expr

        elif isinstance(context, IfNotNull.Context):
            return "ifNotNull(state, scope, {" + ", ".join(repr(n) + ": " + e for n, t, e in context.symbolTypeResult) + "}, lambda state, scope: do(" + ", ".join(context.thenClause) + "), lambda state, scope: do(" + ", ".join(context.elseClause) + "))"

        elif isinstance(context, Doc.Context):
            return "None"

        elif isinstance(context, Error.Context):
            return "error(" + repr(context.message) + ", " + repr(context.code) + ")"

        elif isinstance(context, Log.Context):
            return "self.logger([{}], {})".format(", ".join(x[1] for x in context.exprTypes), context.namespace)

        else:
            raise PFASemanticException("unrecognized context class: " + str(type(context)), "")

class GeneratePythonPure(GeneratePython):
    pass

###########################################################################

class ExecutionState(object):
    def __init__(self, options, routine):
        if routine == "begin":
            self.timeout = options.timeout_begin
        elif routine == "action":
            self.timeout = options.timeout_action
        elif routine == "end":
            self.timeout = options.timeout_end

        self.startTime = time.time()

    def checkTime(self):
        if self.timeout > 0 and (time.time() - self.startTime) * 1000 > self.timeout:
            raise PFATimeoutException("exceeded timeout of {} milliseconds".format(self.timeout))

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

class SharedState(object):
    def __init__(self):
        self.cells = {}
        self.pools = {}

    def __repr__(self):
        return "SharedState({} cells, {} pools)".format(len(self.cells), len(self.pools))

class PersistentStorageItem(object):
    def __init__(self, value, shared, rollback):
        self.value = value
        self.shared = shared
        self.rollback = rollback

class Cell(PersistentStorageItem):
    def __init__(self, value, shared, rollback):
        if shared:
            self.lock = threading.Lock()
        super(Cell, self).__init__(value, shared, rollback)

    def __repr__(self):
        contents = repr(self.value)
        if len(contents) > 30:
            contents = contents[:27] + "..."
        return "Cell(" + ("shared, " if self.shared else "") + ("rollback, " if self.rollback else "") + contents + ")"

    def update(self, path, to):
        if self.shared:
            self.lock.acquire()
            self.value = update(self.value, path, to)
            self.lock.release()
        else:
            self.value = update(self.value, path, to)

    def maybeSaveBackup(self):
        if self.rollback:
            self.oldvalue = self.value

    def maybeRestoreBackup(self):
        if self.rollback:
            self.value = self.oldvalue

class Pool(PersistentStorageItem):
    def __init__(self, value, shared, rollback):
        if shared:
            self.locklock = threading.Lock()
            self.locks = {}
        super(Pool, self).__init__(value, shared, rollback)

    def __repr__(self):
        contents = repr(self.value)
        if len(contents) > 30:
            contents = contents[:27] + "..."
        return "Pool(" + ("shared, " if self.shared else "") + ("rollback, " if self.rollback else "") + contents + ")"

    def update(self, path, to, init):
        head, tail = path[0], path[1:]

        if self.shared:
            self.locklock.acquire()
            if head in self.locks:
                self.locks[head].acquire()
            else:
                self.locks[head] = threading.Lock()
            self.locklock.release()

            if head not in self.value:
                self.value[head] = init
            else:
                self.value[head] = update(self.value[head], tail, to)

            self.locks[head].release()

        else:
            self.value[head] = update(self.value[head], tail, to)

    def maybeSaveBackup(self):
        if self.rollback:
            self.oldvalue = dict(self.value)

    def maybeRestoreBackup(self):
        if self.rollback:
            self.value = self.oldvalue

def call(fcn, state, scope, args):
    callScope = DynamicScope(scope)
    callScope.let(args)
    return fcn(state, callScope)

def update(obj, path, to):
    if len(path) > 0:
        head, tail = path[0], path[1:]

        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                if k == head:
                    out[k] = update(v, tail, to)
                else:
                    out[k] = v
            return out

        elif isinstance(obj, (list, tuple)):
            out = []
            for i, x in enumerate(obj):
                if i == head:
                    out.append(update(x, tail, to))
                else:
                    out.append(x)
            return out

        else:
            raise Exception

    elif callable(to):
        return to(obj)

    else:
        return to
        
def do(*exprs):
    # You've already done them; just return the right value.
    if len(exprs) > 0:
        return exprs[-1]
    else:
        return None

def ifThen(state, scope, predicate, thenClause):
    if predicate(state, DynamicScope(scope)):
        thenClause(state, DynamicScope(scope))
    return None

def ifThenElse(state, scope, predicate, thenClause, elseClause):
    if predicate(state, DynamicScope(scope)):
        return thenClause(state, DynamicScope(scope))
    else:
        return elseClause(state, DynamicScope(scope))

def cond(state, scope, ifThens):
    for predicate, thenClause in ifThens:
        if predicate(state, DynamicScope(scope)):
            thenClause(state, DynamicScope(scope))
            break
    return None

def condElse(state, scope, ifThens, elseClause):
    for predicate, thenClause in ifThens:
        if predicate(state, DynamicScope(scope)):
            return thenClause(state, DynamicScope(scope))
    return elseClause(state, DynamicScope(scope))
    
def doWhile(state, scope, predicate, loopBody):
    predScope = DynamicScope(scope)
    bodyScope = DynamicScope(scope)
    while predicate(state, predScope):
        state.checkTime()
        loopBody(state, bodyScope)
    return None
    
def doUntil(state, scope, predicate, loopBody):
    predScope = DynamicScope(scope)
    bodyScope = DynamicScope(scope)
    while True:
        state.checkTime()
        loopBody(state, bodyScope)
        if predicate(state, predScope):
            break
    return None

def doFor(state, scope, initLet, predicate, stepSet, loopBody):
    loopScope = DynamicScope(scope)
    predScope = DynamicScope(loopScope)
    bodyScope = DynamicScope(loopScope)
    initLet(state, loopScope)
    while predicate(state, predScope):
        state.checkTime()
        loopBody(state, bodyScope)
        stepSet(state, loopScope)
    return None

def doForeach(state, scope, name, array, loopBody):
    loopScope = DynamicScope(scope)
    bodyScope = DynamicScope(loopScope)
    for item in array:
        state.checkTime()
        loopScope.let({name: item})
        loopBody(state, bodyScope)
    return None

def doForkeyval(state, scope, forkey, forval, mapping, loopBody):
    loopScope = DynamicScope(scope)
    bodyScope = DynamicScope(loopScope)
    for key, val in mapping.items():
        state.checkTime()
        loopScope.let({forkey: key, forval: val})
        loopBody(state, bodyScope)
    return None

def cast(state, scope, expr, fromType, cases, partial, parser):
    fromType = parser.getAvroType(fromType)

    for name, toType, clause in cases:
        toType = parser.getAvroType(toType)

        if isinstance(fromType, pfa.datatype.AvroUnion) and isinstance(expr, dict) and len(expr) == 1:
            value, = expr.values()
        else:
            value = expr

        try:
            castValue = pfa.datatype.jsonDecoder(toType, value)
        except AvroException:
            pass
        else:
            clauseScope = DynamicScope(scope)
            clauseScope.let({name: castValue})
            out = clause(state, clauseScope)
            if partial:
                return None
            else:
                return out
    return None

def ifNotNull(state, scope, nameExpr, thenClause, elseClause):
    if all(x is not None for x in nameExpr.values()):
        thenScope = DynamicScope(scope)
        thenScope.let(nameExpr)
        thenClause(state, thenScope)
    else:
        elseClause(state, scope)

def genericLogger(message, namespace):
    if namespace is None:
        print " ".join(map(repr, message))
    else:
        print namespace + ": " + " ".join(map(repr, message))

class PFAEngine(object):
    @staticmethod
    def fromAst(engineConfig, options=None, sharedState=None, multiplicity=1, style="pure", debug=False):
        functionTable = pfa.ast.FunctionTable.blank()
        context, code = engineConfig.walk(GeneratePython.makeTask(style), pfa.ast.SymbolTable.blank(), functionTable)
        if debug:
            print code
        
        sandbox = {# Scoring engine architecture
                   "PFAEngine": PFAEngine,
                   "ExecutionState": ExecutionState,
                   "DynamicScope": DynamicScope,
                   "functionTable": functionTable,
                   # Python statement --> expression wrappers
                   "call": call,
                   "update": update,
                   "do": do,
                   "ifThen": ifThen,
                   "ifThenElse": ifThenElse,
                   "cond": cond,
                   "condElse": condElse,
                   "doWhile": doWhile,
                   "doUntil": doUntil,
                   "doFor": doFor,
                   "doForeach": doForeach,
                   "doForkeyval": doForkeyval,
                   "cast": cast,
                   # Python libraries
                   "math": math,
                   }

        exec(code, sandbox)
        cls = [x for x in sandbox.values() if getattr(x, "__bases__", None) == (PFAEngine,)][0]
        cls.parser = context.parser

        if sharedState is None:
            sharedState = SharedState()

        for cellName, cellConfig in engineConfig.cells.items():
            if cellConfig.shared and cellName not in sharedState.cells:
                value = pfa.datatype.jsonDecoder(cellConfig.avroType, json.loads(cellConfig.init))
                sharedState.cells[cellName] = Cell(value, cellConfig.shared, cellConfig.rollback)

        for poolName, poolConfig in engineConfig.pools.items():
            if poolConfig.shared and poolName not in sharedState.pools:
                if poolConfig.init is None:
                    value = {}
                else:
                    value = pfa.datatype.jsonDecoder(poolConfig.avroType, json.loads(poolConfig.init))
                sharedState.pools[poolName] = Pool(value, poolConfig.shared, poolConfig.rollback)

        out = []
        for index in xrange(multiplicity):
            cells = dict(sharedState.cells)
            pools = dict(sharedState.pools)

            for cellName, cellConfig in engineConfig.cells.items():
                if not cellConfig.shared:
                    value = pfa.datatype.jsonDecoder(cellConfig.avroType, json.loads(cellConfig.init))
                    cells[cellName] = Cell(value, cellConfig.shared, cellConfig.rollback)

            for poolName, poolConfig in engineConfig.pools.items():
                if not poolConfig.shared:
                    if poolConfig.init is None:
                        value = {}
                    else:
                        value = pfa.datatype.jsonDecoder(poolConfig.avroType, json.loads(poolConfig.init))
                        pools[poolName] = Pool(value, poolConfig.shared, poolConfig.rollback)

            out.append(cls(functionTable, cells, pools, pfa.options.EngineOptions(engineConfig.options, options), genericLogger))

        return out

    @staticmethod
    def fromJson(src, options=None, sharedState=None, multiplicity=1, style="pure", debug=False):
        return PFAEngine.fromAst(pfa.reader.jsonToAst(src), options, sharedState, multiplicity, style, debug)

    @staticmethod
    def fromYaml(src, options=None, sharedState=None, multiplicity=1, style="pure", debug=False):
        return PFAEngine.fromAst(pfa.reader.yamlToAst(src), options, sharedState, multiplicity, style, debug)
