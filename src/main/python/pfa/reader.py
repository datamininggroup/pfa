#!/usr/bin/env python

import json
import base64

import pfa.util

from pfa.ast import validSymbolName
from pfa.ast import validFunctionName
from pfa.ast import Ast
from pfa.ast import Method
from pfa.ast import EngineConfig
from pfa.ast import Cell
from pfa.ast import Pool
from pfa.ast import Argument
from pfa.ast import Expression
from pfa.ast import LiteralValue
from pfa.ast import PathIndex
from pfa.ast import ArrayIndex
from pfa.ast import MapIndex
from pfa.ast import RecordIndex
from pfa.ast import HasPath
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
from pfa.ast import Doc
from pfa.ast import Error
from pfa.ast import Log
from pfa.errors import PFASyntaxException
from pfa.types import AvroTypeBuilder

def jsonToAst(jsonInput):
    if isinstance(jsonInput, file):
        jsonInput = jsonInput.read()
    if isinstance(jsonInput, basestring):
        jsonInput = json.loads(jsonInput)
    
    avroTypeBuilder = AvroTypeBuilder()
            
    result = _readEngineConfig(jsonInput, avroTypeBuilder)
    avroTypeBuilder.resolveTypes()
    return result

def yamlToAst(yamlInput):
    import yaml
    if isinstance(yamlInput, file):
        yamlInput = yamlInput.read()
    return jsonToAst(yaml.load(yamlInput))

def jsonToExpressionAst(jsonInput):
    if isinstance(jsonInput, file):
        jsonInput = jsonInput.read()
    if isinstance(jsonInput, basestring):
        jsonInput = json.loads(jsonInput)

    avroTypeBuilder = AvroTypeBuilder()

    result = _readExpression(jsonInput, "", avroTypeBuilder)
    avroTypeBuilder.resolveTypes()
    return result

jsonToAst.expr = jsonToExpressionAst

def jsonToExpressionsAst(jsonInput):
    if isinstance(jsonInput, file):
        jsonInput = jsonInput.read()
    if isinstance(jsonInput, basestring):
        jsonInput = json.loads(jsonInput)

    avroTypeBuilder = AvroTypeBuilder()

    result = _readExpressionArray(jsonInput, "", avroTypeBuilder)
    avroTypeBuilder.resolveTypes()
    return result

jsonToAst.exprs = jsonToExpressionsAst

def jsonToFcnDef(jsonInput):
    if isinstance(jsonInput, file):
        jsonInput = jsonInput.read()
    if isinstance(jsonInput, basestring):
        jsonInput = json.loads(jsonInput)

    avroTypeBuilder = AvroTypeBuilder()
    
    result = _readFcnDef(jsonInput, "", avroTypeBuilder)
    avroTypeBuilder.resolveTypes()
    return result

jsonToAst.fcn = jsonToFcnDef

def jsonToFcnDefs(jsonInput):
    if isinstance(jsonInput, file):
        jsonInput = jsonInput.read()
    if isinstance(jsonInput, basestring):
        jsonInput = json.loads(jsonInput)

    avroTypeBuilder = AvroTypeBuilder()
    
    result = _readFcnDefMap(jsonInput, "", avroTypeBuilder)
    avroTypeBuilder.resolveTypes()
    return result

jsonToAst.fcns = jsonToFcnDefs

def _trunc(x):
    if len(x) > 30:
        return x[:27] + "..."
    else:
        return x

def _stripAtSigns(data):
    if isinstance(data, dict):
        return dict((k, _stripAtSigns(v)) for k, v in data.items() if k != "@")
    elif isinstance(data, (list, tuple)):
        return [_stripAtSigns(x) for x in data]
    else:
        return data

def _readEngineConfig(data, avroTypeBuilder):
    if not isinstance(data, dict):
        raise PFASyntaxException("PFA engine must be a JSON object, not " + _trunc(repr(data)), "")

    keys = set(x for x in data.keys() if x != "@")

    _method = Method.MAP
    _begin = []
    _end = []
    _fcns = {}
    _zero = None
    _cells = {}
    _pools = {}
    _randseed = None
    _doc = None
    _metadata = None
    _options = {}

    for key in keys:
        if key == "name": _name = _readString(data[key], key)
        elif key == "method":
            x = _readString(data[key], key)
            if x == "map":
                _method = Method.MAP
            elif x == "emit":
                _method = Method.EMIT
            elif x == "fold":
                _method = Method.FOLD
            else:
                raise PFASyntaxException("expected one of \"map\", \"emit\", \"fold\", not \"{}\"".format(x), "")
        elif key == "input": _input = _readAvroPlaceholder(data[key], key, avroTypeBuilder)
        elif key == "output": _output = _readAvroPlaceholder(data[key], key, avroTypeBuilder)
        elif key == "begin":
            if isinstance(data[key], (list, tuple)):
                _begin = _readExpressionArray(data[key], key, avroTypeBuilder)
            else:
                _begin = [_readExpression(data[key], key, avroTypeBuilder)]
        elif key == "action":
            if isinstance(data[key], (list, tuple)):
                _action = _readExpressionArray(data[key], key, avroTypeBuilder)
            else:
                _action = [_readExpression(data[key], key, avroTypeBuilder)]
        elif key == "end":
            if isinstance(data[key], (list, tuple)):
                _end = _readExpressionArray(data[key], key, avroTypeBuilder)
            else:
                _end = [_readExpression(data[key], key, avroTypeBuilder)]
        elif key == "fcns": _fcns = _readFcnDefMap(data[key], key, avroTypeBuilder)
        elif key == "zero": _zero = _readJsonToString(data[key], key)
        elif key == "cells": _cells = _readCells(data[key], key, avroTypeBuilder)
        elif key == "pools": _pools = _readPools(data[key], key, avroTypeBuilder)
        elif key == "randseed": _randseed = _readLong(data[key], key)
        elif key == "doc": _doc = _readString(data[key], key)
        elif key == "metadata": _metadata = _readJsonNode(data[key], key)
        elif key == "options": _options = _readJsonNodeMap(data[key], key)
        else:
            raise PFASyntaxException("unexpected top-level field: {}".format(key), "")

    if "name" not in keys:
        _name = pfa.util.uniqueEngineName()

    if _method == Method.FOLD and "zero" not in keys:
        raise PFASyntaxException("folding engines must include a \"zero\" to begin the calculation", "")

    required = set(["action", "input", "output"])
    if keys.intersection(required) != required:
        raise PFASyntaxException("missing top-level fields: {}".format(", ".join(required.diff(fields))), "")
    else:
        return EngineConfig(_name, _method, _input, _output, _begin, _action, _end, _fcns, _zero, _cells, _pools, _randseed, _doc, _metadata, _options, "")

def _readJsonToString(data, dot):
    return json.dumps(_stripAtSigns(data))

def _readJsonNode(data, dot):
    return _stripAtSigns(data)

def _readAvroPlaceholder(data, dot, avroTypeBuilder):
    return avroTypeBuilder.makePlaceholder(json.dumps(_stripAtSigns(data)))

def _readJsonNodeMap(data, dot):
    if isinstance(data, dict):
        return _stripAtSigns(data)
    else:
        raise PFASyntaxException("expected map of JSON objects, not " + _trunc(repr(data)), dot)

def _readJsonToStringMap(data, dot):
    if isinstance(data, dict):
        return dict((k, _readJsonToString(v, dot + "." + k)) for k, v in data.items() if k != "@")
    else:
        raise PFASyntaxException("expected map of JSON objects, not " + _trunc(repr(data)), dot)

def _readBoolean(data, dot):
    if isinstance(data, bool):
        return data
    else:
        raise PFASyntaxException("expected boolean, not " + _trunc(repr(data)), dot)

def _readInt(data, dot):
    if isinstance(data, int):
        if -2147483648 <= data <= 2147483647:
            return data
        else:
            raise PFASyntaxException("int out of range: {}".format(data), dot)
    else:
        raise PFASyntaxException("expected int, not " + _trunc(repr(data)), dot)

def _readLong(data, dot):
    if isinstance(data, (int, long)):
        if -9223372036854775808 <= data <= 9223372036854775807:
            return data
        else:
            raise PFASyntaxException("long out of range: {}".format(data), dot)
    else:
        raise PFASyntaxException("expected long, not " + _trunc(repr(data)), dot)

def _readFloat(data, dot):
    if isinstance(data, (int, long, float)):
        return float(data)
    else:
        raise PFASyntaxException("expected float, not " + _trunc(repr(data)), dot)

def _readDouble(data, dot):
    if isinstance(data, (int, long, float)):
        return float(data)
    else:
        raise PFASyntaxException("expected double, not " + _trunc(repr(data)), dot)

def _readStringArray(data, dot):
    if isinstance(data, (list, tuple)):
        return [_readString(x, dot + "." + str(i)) for i, x in enumerate(data)]
    else:
        raise PFASyntaxException("expected array of strings, not " + _trunc(repr(data)), dot)

def _readString(data, dot):
    if isinstance(data, basestring):
        return data
    else:
        raise PFASyntaxException("expected string, not " + _trunc(repr(data)), dot)

def _readBase64(data, dot):
    if isinstance(data, basestring):
        return base64.b64decode(data)
    else:
        raise PFASyntaxException("expected base64 data, not " + _trunc(repr(data)), dot)

def _readExpressionArray(data, dot, avroTypeBuilder):
    if isinstance(data, (list, tuple)):
        return [_readExpression(x, dot + "." + str(i), avroTypeBuilder) for i, x in enumerate(data)]
    else:
        raise PFASyntaxException("expected array of expressions, not " + _trunc(repr(data)), dot)

def _readExpressionMap(data, dot, avroTypeBuilder):
    if isinstance(data, dict):
        return dict((k, _readExpression(v, dot + "." + k, avroTypeBuilder)) for k, v in data.items() if k != "@")
    else:
        raise PFASyntaxException("expected map of expressions, not " + _trunc(repr(data)), dot)

def _readCastCaseArray(data, dot, avroTypeBuilder):
    if isinstance(data, (list, tuple)):
        return [_readCastCase(x, dot + "." + str(i), avroTypeBuilder) for i, x in enumerate(data)]
    else:
        raise PFASyntaxException("expected array of cast-cases, not " + _trunc(repr(data)), dot)

def _readCastCase(data, dot, avroTypeBuilder):
    if isinstance(data, dict):
        keys = set(x for x in data.keys() if x != "@")

        for key in keys:
            if key == "as": _as = _readAvroPlaceholder(data[key], dot + "." + key, avroTypeBuilder)
            elif key == "named": _named = _readString(data[key], dot + "." + key)
            elif key == "do":
                if isinstance(data[key], (list, tuple)):
                    _body = _readExpressionArray(data[key], dot + "." + key, avroTypeBuilder)
                else:
                    _body = [_readExpression(data[key], dot + "." + key, avroTypeBuilder)]
            else:
                raise PFASyntaxException("unexpected field in cast-case: {}".format(key), dot)

    if "named" in keys and not validSymbolName(_named):
        raise PFASyntaxException("\"{}\" is not a valid symbol name".format(_named), dot)

    required = set(["as", "named", "do"])
    if (keys != required):
        raise PFASyntaxException("wrong set of fields for a cast-case: \"{}\"".format(", ".join(keys)), dot)
    else:
        return CastCase(_as, _named, _body)

def _readExpression(data, dot, avroTypeBuilder):
    out = _readArgument(data, dot, avroTypeBuilder)
    if isinstance(out, Expression):
        return out
    else:
        raise PFASyntaxException("argument appears outside of argument list", dot)

def _readArgumentArray(data, dot, avroTypeBuilder):
    if isinstance(data, (list, tuple)):
        return [_readArgument(x, dot + "." + str(i), avroTypeBuilder) for i, x in enumerate(data)]
    else:
        raise PFASyntaxException("expected array of arguments, not " + _trunc(repr(data)), dot)

def _readArgument(data, dot, avroTypeBuilder):
    if data is None:
        return LiteralNull(dot)
    elif isinstance(data, bool):
        return LiteralBoolean(data, dot)
    elif isinstance(data, int):
        if -2147483648 <= data <= 2147483647:
            return LiteralInt(data, dot)
        elif -9223372036854775808 <= data <= 9223372036854775807:
            return LiteralLong(data, dot)
        else:
            raise PFASyntaxException("integer out of range: " + str(data), dot)
    elif isinstance(data, float):
        return LiteralDouble(data, dot)
    elif isinstance(data, basestring):
        if validSymbolName(data):
            return Ref(data, dot)
        else:
            raise PFASyntaxException("\"{}\" is not a valid symbol name" + str(data), dot)

    elif isinstance(data, (list, tuple)):
        if len(data) == 1 and isinstance(data[0], basestring):
            return LiteralString(data[0])
        else:
            raise PFASyntaxException("expecting expression, which may be [\"string\"], but no other array can be used as an expression", dot)

    elif isinstance(data, dict):
        keys = set(x for x in data.keys() if x != "@")

        _path = []
        _init = None
        _seq = False
        _partial = False
        _code = 0
        _newObject = None
        _newArray = None

        for key in keys:
            if key == "int": _int = _readInt(data[key], dot + "." + key)
            elif key == "long": _long = _readLong(data[key], dot + "." + key)
            elif key == "float": _float = _readFloat(data[key], dot + "." + key)
            elif key == "double": _double = _readDouble(data[key], dot + "." + key)
            elif key == "string": _string = _readString(data[key], dot + "." + key)
            elif key == "base64": _bytes = _readBase64(data[key], dot + "." + key)
            elif key == "type": _avroType = _readAvroPlaceholder(data[key], dot + "." + key, avroTypeBuilder)
            elif key == "value": _value = _readJsonToString(data[key], dot + "." + key)

            elif key == "let": _let = _readExpressionMap(data[key], dot + "." + key, avroTypeBuilder)
            elif key == "set": _set = _readExpressionMap(data[key], dot + "." + key, avroTypeBuilder)
            elif key == "for": _forlet = _readExpressionMap(data[key], dot + "." + key, avroTypeBuilder)
            elif key == "step": _forstep = _readExpressionMap(data[key], dot + "." + key, avroTypeBuilder)

            elif key == "do":
                if isinstance(data[key], (list, tuple)):
                    _body = _readExpressionArray(data[key], dot + "." + key, avroTypeBuilder)
                else:
                    _body = [_readExpression(data[key], dot + "." + key, avroTypeBuilder)]
            elif key == "then":
                if isinstance(data[key], (list, tuple)):
                    _thenClause = _readExpressionArray(data[key], dot + "." + key, avroTypeBuilder)
                else:
                    _thenClause = [_readExpression(data[key], dot + "." + key, avroTypeBuilder)]
            elif key == "else":
                if isinstance(data[key], (list, tuple)):
                    _elseClause = _readExpressionArray(data[key], dot + "." + key, avroTypeBuilder)
                else:
                    _elseClause = [_readExpression(data[key], dot + "." + key, avroTypeBuilder)]
            elif key == "log":
                if isinstance(data[key], (list, tuple)):
                    _log = _readExpressionArray(data[key], dot + "." + key, avroTypeBuilder)
                else:
                    _log = [_readExpression(data[key], dot + "." + key, avroTypeBuilder)]
            elif key == "path":
                _path = _readExpressionArray(data[key], dot + "." + key, avroTypeBuilder)

            elif key == "if": _ifPredicate = _readExpression(data[key], dot + "." + key, avroTypeBuilder)
            elif key == "while": _whilePredicate = _readExpression(data[key], dot + "." + key, avroTypeBuilder)
            elif key == "until": _until = _readExpression(data[key], dot + "." + key, avroTypeBuilder)

            elif key == "cond":
                _cond = _readExpressionArray(data[key], dot + "." + key, avroTypeBuilder)
                if any(x.elseClause is not None for x in _cond):
                    raise PFASyntaxException("cond expression must only contain else-less if expressions", dot)

            elif key == "cases": _cases = _readCastCaseArray(data[key], dot + "." + key, avroTypeBuilder)

            elif key == "foreach": _foreach = _readString(data[key], dot + "." + key)
            elif key == "forkey": _forkey = _readString(data[key], dot + "." + key)
            elif key == "forval": _forval = _readString(data[key], dot + "." + key)
            elif key == "fcnref": _fcnref = _readString(data[key], dot + "." + key)
            elif key == "attr": _attr = _readString(data[key], dot + "." + key)
            elif key == "cell": _cell = _readString(data[key], dot + "." + key)
            elif key == "pool": _pool = _readString(data[key], dot + "." + key)

            elif key == "in": _in = _readExpression(data[key], dot + "." + key, avroTypeBuilder)
            elif key == "cast": _cast = _readExpression(data[key], dot + "." + key, avroTypeBuilder)
            elif key == "upcast": _upcast = _readExpression(data[key], dot + "." + key, avroTypeBuilder)
            elif key == "init": _init = _readExpression(data[key], dot + "." + key, avroTypeBuilder)

            elif key == "seq": _seq = _readBoolean(data[key], dot + "." + key)
            elif key == "partial": _partial = _readBoolean(data[key], dot + "." + key)

            elif key == "doc": _doc = _readString(data[key], dot + "." + key)
            elif key == "error": _error = _readString(data[key], dot + "." + key)
            elif key == "code": _code = _readInt(data[key], dot + "." + key)
            elif key == "namespace": _namespace = _readString(data[key], dot + "." + key)

            elif key == "new":
                if isinstance(data[key], dict):
                    _newObject = _readExpressionMap(data[key], dot + "." + key, avroTypeBuilder)
                elif isinstance(data[key], (list, tuple)):
                    _newArray = _readExpressionArray(data[key], dot + "." + key, avroTypeBuilder)
                else:
                    raise PFASyntaxException("\"new\" must be an object (map, record) or an array", dot)

            elif key == "params": _params = _readParams(data[key], dot + "." + key, avroTypeBuilder)
            elif key == "ret": _ret = _readAvroPlaceholder(data[key], dot + "." + key, avroTypeBuilder)
            elif key == "as": _as = _readAvroPlaceholder(data[key], dot + "." + key, avroTypeBuilder)

            elif key == "to": _to = _readArgument(data[key], dot + "." + key, avroTypeBuilder)

            else:
                _callName = key
                if isinstance(data[key], (list, tuple)):
                    _callArgs = _readArgumentArray(data[key], dot + "." + key, avroTypeBuilder)
                else:
                    _callArgs = [_readArgument(data[key], dot + "." + key, avroTypeBuilder)]

        if "foreach" in keys and not validSymbolName(_foreach):
            raise PFASyntaxException("\"{}\" is not a valid symbol name".format(data[keys]), dot)
        if "forkey" in keys and not validSymbolName(_forkey):
            raise PFASyntaxException("\"{}\" is not a valid symbol name".format(data[keys]), dot)
        if "forval" in keys and not validSymbolName(_forval):
            raise PFASyntaxException("\"{}\" is not a valid symbol name".format(data[keys]), dot)
        if "fcnref" in keys and not validFunctionName(_fcnref):
            raise PFASyntaxException("\"{}\" is not a valid function name".format(data[keys]), dot)

        if keys == set(["int"]):                             return LiteralInt(_int, dot)
        elif keys == set(["long"]):                          return LiteralLong(_long, dot)
        elif keys == set(["float"]):                         return LiteralFloat(_float, dot)
        elif keys == set(["double"]):                        return LiteralDouble(_double, dot)
        elif keys == set(["string"]):                        return LiteralString(_string, dot)
        elif keys == set(["base64"]):                        return LiteralBase64(_bytes, dot)
        elif keys == set(["type", "value"]):                 return Literal(_avroType, _value, dot)

        elif keys == set(["new", "type"]) and _newObject is not None:
                                                             return NewObject(_newObject, _avroType, avroTypeBuilder, dot)
        elif keys == set(["new", "type"]) and _newArray is not None:
                                                             return NewArray(_newArray, _avroType, avroTypeBuilder, dot)

        elif keys == set(["do"]):                            return Do(_body, dot)
        elif keys == set(["let"]):                           return Let(_let, dot)
        elif keys == set(["set"]):                           return SetVar(_set, dot)

        elif keys == set(["attr", "path"]):                  return AttrGet(_attr, _path, dot)
        elif keys == set(["attr", "path", "to"]):            return AttrTo(_attr, _path, _to, dot)
        elif keys == set(["cell"]) or \
             keys == set(["cell", "path"]):                  return CellGet(_cell, _path, dot)
        elif keys == set(["cell", "to"]) or \
             keys == set(["cell", "path", "to"]):            return CellTo(_cell, _path, _to, dot)
        elif keys == set(["pool", "path"]):                  return PoolGet(_pool, _path, dot)
        elif keys == set(["pool", "path", "to"]) or \
             keys == set(["pool", "path", "to", "init"]):    return PoolTo(_pool, _path, _to, _init, dot)

        elif keys == set(["if", "then"]):                    return If(_ifPredicate, _thenClause, None, dot)
        elif keys == set(["if", "then", "else"]):            return If(_ifPredicate, _thenClause, _elseClause, dot)
        elif keys == set(["cond"]):                          return Cond(_cond, None, dot)
        elif keys == set(["cond", "else"]):                  return Cond(_cond, _elseClause, dot)

        elif keys == set(["while", "do"]):                   return While(_whilePredicate, _body, dot)
        elif keys == set(["do", "until"]):                   return DoUntil(_body, _until, dot)
        elif keys == set(["for", "until", "step", "do"]):    return For(_forlet, _until, _forstep, _body, dot)

        elif keys == set(["foreach", "in", "do"]) or \
             keys == set(["foreach", "in", "do", "seq"]):    return Foreach(_foreach, _in, _body, _seq, dot)
        elif keys == set(["forkey", "forval", "in", "do"]):  return Forkeyval(_forkey, _forval, _in, _body, dot)

        elif keys == set(["cast", "cases"]) or \
             keys == set(["cast", "cases", "partial"]):      return CastBlock(_cast, _cases, _partial, dot)
        elif keys == set(["upcast", "as"]):                  return Upcast(_upcast, _as, dot)

        elif keys == set(["doc"]):                           return Doc(_doc, dot)

        elif keys == set(["error"]):                         return Error(_error, None, dot)
        elif keys == set(["error", "code"]):                 return Error(_error, _code, dot)
        elif keys == set(["log"]):                           return Log(_log, None, dot)
        elif keys == set(["log", "namespace"]):              return Log(_log, _namespace, dot)

        elif keys == set(["params", "ret", "do"]):           return FcnDef(_params, _ret, _body, dot)
        elif keys == set(["fcnref"]):                        return FcnRef(_fcnref, dot)

        elif len(keys) == 1 and list(keys)[0] not in \
             set(["as", "base64", "cases", "cast", "cell", "code", "cond", "do", "doc", "double", "else", "error", "fcnref",
                  "float", "for", "foreach", "forkey", "forval", "if", "in", "init", "int", "let", "log", "long",
                  "namespace", "new", "params", "partial", "path", "pool", "ret", "seq", "set", "step", "string", "then",
                  "to", "type", "upcast", "until", "value", "while"]):
                                                             return Call(_callName, _callArgs, dot)

        else: raise PFASyntaxException("not enough arguments for special form: {}".format(", ".join(keys)), dot)

    else:
        raise PFASyntaxException("expected expression, not " + _trunc(repr(data)), dot)

def _readFcnDefMap(data, dot, avroTypeBuilder):
    if isinstance(data, dict):
        for k in data.keys():
            if k != "@" and not validFunctionName(k):
                raise PFASyntaxException("\"{}\" is not a valid function name".format(k), dot)
        return dict((k, _readFcnDef(v, dot + "." + k, avroTypeBuilder)) for k, v in data.items() if k != "@")
    else:
        raise PFASyntaxException("expected map of function definitions, not " + _trunc(repr(data)), dot)

def _readFcnDef(data, dot, avroTypeBuilder):
    if isinstance(data, dict):
        keys = set(x for x in data.keys() if x != "@")

        for key in keys:
            if key == "params": _params = _readParams(data[key], dot + "." + key, avroTypeBuilder)
            elif key == "ret": _ret = _readAvroPlaceholder(data[key], dot + "." + key, avroTypeBuilder)
            elif key == "do":
                if isinstance(data[key], (list, tuple)):
                    _body = _readExpressionArray(data[key], dot + "." + key, avroTypeBuilder)
                else:
                    _body = [_readExpression(data[key], dot + "." + key, avroTypeBuilder)]
            else:
                raise PFASyntaxException("unexpected field in function definition: " + key, dot)

        required = set(["params", "ret", "do"])
        if (keys != required):
            raise PFASyntaxException("wrong set of fields for a function definition: " + ", ".join(keys), dot)
        else:
            return FcnDef(_params, _ret, _body, dot)
    else:
        raise PFASyntaxException("expected function definition, not " + _trunc(repr(data)), dot)

def _readParams(data, dot, avroTypeBuilder):
    if isinstance(data, (list, tuple)):
        return [_readParam(x, dot + "." + str(i), avroTypeBuilder) for i, x in enumerate(data)]
    else:
        raise PFASyntaxException("expected array of function parameters, not " + _trunc(repr(data)), dot)

def _readParam(data, dot, avroTypeBuilder):
    if isinstance(data, dict):
        keys = set(x for x in data.keys() if x != "@")
        if len(keys) != 1:
            raise PFASyntaxException("function parameter name-type map should have only one pair", dot)
        n = list(keys)[0]
        if not validSymbolName(n):
            raise PFASyntaxException("\"{}\" is not a valid symbol name".format(n))

        t = _readAvroPlaceholder(data[n], dot + "." + n, avroTypeBuilder)
        return {n: t}
    else:
        raise PFASyntaxException("expected function parameter name-type singleton map, not " + _trunc(repr(data)), dot)

def _readCells(data, dot, avroTypeBuilder):
    if isinstance(data, dict):
        for k in data.keys():
            if k != "@" and not validSymbolName(k):
                raise PFASyntaxException("\"{}\" is not a valid symbol name".format(k), dot)
        return dict((k, _readCell(data[k], dot, avroTypeBuilder)) for k, v in data.items() if k != "@")
    else:
        raise PFASyntaxException("expected map of cells, not " + _trunc(repr(data)), dot)

def _readCell(data, dot, avroTypeBuilder):
    if isinstance(data, dict):
        _shared = False
        keys = set(x for x in data.keys() if x != "@")
        for key in keys:
            if key == "type": _avroType = _readAvroPlaceholder(data[key], dot + "." + key, avroTypeBuilder)
            elif key == "init": _init = _readJsonToString(data[key], dot + "." + key)
            elif key == "shared": _shared = _readBoolean(data[key], dot + "." + key)

        required = set(["type", "init"])
        if keys.intersection(required) != required:
            raise PFASyntaxException("wrong set of fields for a cell: " + ", ".join(keys), dot)
        else:
            return Cell(_avroType, _init, _shared, dot)
    else:
        raise PFASyntaxException("expected cell, not " + _trunc(repr(data)), dot)

def _readPools(data, dot, avroTypeBuilder):
    if isinstance(data, dict):
        for k in data.keys():
            if k != "@" and not validSymbolName(k):
                raise PFASyntaxException("\"{}\" is not a valid symbol name".format(k), dot)
        return dict((k, _readPool(data[k], dot, avroTypeBuilder)) for k, v in data.items() if k != "@")
    else:
        raise PFASyntaxException("expected map of pools, not " + _trunc(repr(data)), dot)

def _readPool(data, dot, avroTypeBuilder):
    if isinstance(data, dict):
        _shared = False
        keys = set(x for x in data.keys() if x != "@")
        for key in keys:
            if key == "type": _avroType = _readAvroPlaceholder(data[key], dot + "." + key, avroTypeBuilder)
            elif key == "init": _init = _readJsonToStringMap(data[key], dot + "." + key)
            elif key == "shared": _shared = _readBoolean(data[key], dot + "." + key)

        required = set(["type", "init"])
        if keys.intersection(required) != required:
            raise PFASyntaxException("wrong set of fields for a pool: " + ", ".join(keys), dot)
        else:
            return Pool(_avroType, _init, _shared, dot)
    else:
        raise PFASyntaxException("expected pool, not " + _trunc(repr(data)), dot)
