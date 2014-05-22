#!/usr/bin/env python

import json

import avro.io
import avro.schema

import pfa.errors
import pfa.util

######################################################### the most general types

class Type(object):
    @property
    def avroType(self): raise TypeError

class FcnType(Type):
    def __init__(self, params, ret):
        self._params = params
        self._ret = ret

    @property
    def params(self):
        return self._params

    @property
    def ret(self):
        return self._ret

    def accepts(self, other):
        if isinstance(self, FcnType):
            return len(self.params) == len(other.params) and \
                   all(y.accepts(x) for x, y in zip(self.params, other.params)) and \
                   self.ret.accepts(other.ret)
        else:
            return False

    def __eq__(self, other):
        if isinstance(other, FcnType):
            return self.params == other.params and self.ret == other.ret
        else:
            return False

    def __repr__(self):
        return '{{"type": "function", "params": [{params}], "ret": {ret}}}'.format(
            params=",".join(repr(x) for x in self.params),
            ret=repr(self.ret))

######################################################### Avro types

def schemaToAvroType(schema):
    if schema.type == "null":
        return AvroNull()
    elif schema.type == "boolean":
        return AvroBoolean()
    elif schema.type == "int":
        return AvroInt()
    elif schema.type == "long":
        return AvroLong()
    elif schema.type == "float":
        return AvroFloat()
    elif schema.type == "double":
        return AvroDouble()
    elif schema.type == "bytes":
        return AvroBytes()
    elif schema.type == "fixed":
        out = AvroFixed.__new__(AvroFixed)
        out._schema = schema
        return out
    elif schema.type == "string":
        return AvroString()
    elif schema.type == "enum":
        out = AvroEnum.__new__(AvroEnum)
        out._schema = schema
        return out
    elif schema.type == "array":
        return AvroArray(schemaToAvroType(schema.items))
    elif schema.type == "map":
        return AvroMap(schemaToAvroType(schema.values))
    elif schema.type == "record":
        out = AvroRecord.__new__(AvroRecord)
        out._schema = schema
        return out
    elif schema.type == "union":
        out = AvroUnion.__new__(AvroUnion)
        out._schema = schema
        return out

def avroTypeToSchema(avroType):
    return avroType.schema

class AvroType(Type):
    @property
    def schema(self):
        return self._schema

    def __eq__(self, other):
        if isinstance(other, AvroType):
            return self.schema == other.schema
        elif isinstance(other, AvroPlaceholder):
            return self.schema == other.avroType.schema
        else:
            return False

    def __hash__(self):
        return hash(self.schema)

    def _recordFieldsOkay(self, other, memo, checkRecord):
        for xf in self.fields:
            if xf.default is None:
                if not any(xf.name == yf.name and xf.avroType.accepts(yf.avroType, memo, checkRecord) for yf in other.fields):
                    return False
            else:
                # not having a matching name in y is fine: x has a default
                # but having a matching name with a mismatched type is bad
                # (spec isn't clear, but org.apache.avro.SchemaCompatibility works that way)
                for yf in other.fields:
                    if xf.name == yf.name:
                        if not xf.avroType.accepts(yf.avroType, memo, checkRecord):
                            return False
        return True

    # self == "reader" (the anticipated signature, pattern to be matched),
    # other == "writer" (the given fact, argument to be accepted or rejected)
    # the special cases handle situations in which Python-Avro fails to be fully covariant
    def accepts(self, other, memo=None, checkRecord=True):
        if isinstance(self, AvroNull) and isinstance(other, AvroNull):
            return True
        elif isinstance(self, AvroBoolean) and isinstance(other, AvroBoolean):
            return True
        elif isinstance(self, AvroBytes) and isinstance(other, AvroBytes):
            return True
        elif isinstance(self, AvroString) and isinstance(other, AvroString):
            return True

        elif isinstance(self, AvroInt) and isinstance(other, AvroInt):
            return True
        elif isinstance(self, AvroLong) and (isinstance(other, AvroInt) or isinstance(other, AvroLong)):
            return True
        elif isinstance(self, AvroFloat) and (isinstance(other, AvroInt) or isinstance(other, AvroLong) or isinstance(other, AvroFloat)):
            return True
        elif isinstance(self, AvroDouble) and (isinstance(other, AvroInt) or isinstance(other, AvroLong) or isinstance(other, AvroFloat) or isinstance(other, AvroDouble)):
            return True

        elif isinstance(self, AvroArray) and isinstance(other, AvroArray):
            return self.items.accepts(other.items, memo, checkRecord)

        elif isinstance(self, AvroMap) and isinstance(other, AvroMap):
            return self.values.accepts(other.values, memo, checkRecord)

        elif isinstance(self, AvroFixed) and isinstance(other, AvroFixed):
            return self.size == other.size and self.fullName == other.fullName

        elif isinstance(self, AvroEnum) and isinstance(other, AvroEnum):
            return set(other.symbols).issubset(set(self.symbols)) and self.fullName == other.fullName

        elif isinstance(self, AvroRecord) and isinstance(other, AvroRecord):
            if memo is None:
                memo = set()
            else:
                memo = set(memo)

            if checkRecord and other.fullName not in memo:
                if not self._recordFieldsOkay(other, memo, checkRecord=False):
                    return False

                memo.add(self.fullName)

                if not self._recordFieldsOkay(other, memo, checkRecord):
                    return False

            return self.fullName == other.fullName

        elif isinstance(self, AvroUnion) and isinstance(other, AvroUnion):
            for yt in other.types:
                if not any(xt.accepts(yt, memo, checkRecord) for xt in self.types):
                    return False
            return True

        elif isinstance(self, AvroUnion):
            return any(xt.accepts(other, memo, checkRecord) for xt in self.types)

        elif isinstance(other, AvroUnion):
            return all(self.accepts(yt, memo, checkRecord) for yt in other.types)

        else:
            return False

    @property
    def avroType(self): return self

    def __repr__(self):
        return json.dumps(self.schema.to_json())

class AvroCompiled(AvroType):
    @property
    def name(self):
        return self.schema.name
    @property
    def namespace(self):
        return self.schema.namespace
    @property
    def fullName(self):
        return self.schema.fullname

class AvroNumber(AvroType): pass
class AvroRaw(AvroType): pass
class AvroIdentifier(AvroType): pass
class AvroContainer(AvroType): pass
class AvroMapping(AvroType): pass

######################################################### Avro type wrappers

class AvroNull(AvroType):
    _schema = avro.schema.PrimitiveSchema("null")
class AvroBoolean(AvroType):
    _schema = avro.schema.PrimitiveSchema("boolean")
class AvroInt(AvroNumber):
    _schema = avro.schema.PrimitiveSchema("int")
class AvroLong(AvroNumber):
    _schema = avro.schema.PrimitiveSchema("long")
class AvroFloat(AvroNumber):
    _schema = avro.schema.PrimitiveSchema("float")
class AvroDouble(AvroNumber):
    _schema = avro.schema.PrimitiveSchema("double")
class AvroBytes(AvroRaw):
    _schema = avro.schema.PrimitiveSchema("bytes")

class AvroFixed(AvroRaw, AvroCompiled):
    def __init__(self, size, name=None, namespace=None):
        if name is None:
            name = pfa.util.uniqueFixedName()
        self._schema = avro.schema.FixedSchema(name, namespace, size, avro.schema.Names())
    @property
    def size(self):
        return self.schema.size

class AvroString(AvroIdentifier): 
    _schema = avro.schema.PrimitiveSchema("string")

class AvroEnum(AvroIdentifier, AvroCompiled):
    def __init__(self, symbols, name=None, namespace=None):
        if name is None:
            name = pfa.util.uniqueEnumName()
        self._schema = avro.schema.EnumSchema(name, namespace, symbols, avro.schema.Names())
    @property
    def symbols(self):
        return self.schema.symbols

class AvroArray(AvroContainer):
    def __init__(self, items):
        self._schema = avro.schema.ArraySchema("null", avro.schema.Names())
        self._schema.set_prop("items", items.schema)
    @property
    def items(self):
        return schemaToAvroType(self.schema.items)

class AvroMap(AvroContainer, AvroMapping):
    def __init__(self, values):
        self._schema = avro.schema.MapSchema("null", avro.schema.Names())
        self._schema.set_prop("values", values.schema)
    @property
    def values(self):
        return schemaToAvroType(self.schema.values)

class AvroRecord(AvroContainer, AvroMapping, AvroCompiled):
    def __init__(self, fields, name=None, namespace=None):
        if name is None:
            name = pfa.util.uniqueRecordName()
        self._schema = avro.schema.RecordSchema(name, namespace, [], avro.schema.Names(), "record")
        self._schema.set_prop("fields", [x.schema for x in fields])
    @property
    def fields(self):
        return [AvroField.fromSchema(x) for x in self.schema.fields]
    @property
    def fieldsDict(self):
        return dict((x.name, x) for x in self.fields)
    def field(self, name):
        return self.fieldsDict[name]
    @property
    def fieldsDict(self):
        return dict((x.name, AvroField.fromSchema(x)) for x in self.schema.fields)

class AvroUnion(AvroType):
    def __init__(self, types):
        self._schema = avro.schema.UnionSchema([], avro.schema.Names())
        self._schema._schemas = [x.schema for x in types]
    @property
    def types(self):
        return [schemaToAvroType(x) for x in self._schema._schemas]

class AvroField(object):
    @staticmethod
    def fromSchema(schema):
        out = AvroField.__new__(AvroField)
        out._schema = schema
        return out
    def __init__(self, name, avroType, default=None, order=None):
        self._schema = avro.schema.Field(avroType.schema.to_json(), name, default is not None, default, order, avro.schema.Names())
    @property
    def schema(self):
        return self._schema
    def __repr__(self):
        return json.dumps(self.schema.to_json())
    @property
    def name(self):
        return self.schema.name
    @property
    def avroType(self):
        return schemaToAvroType(self.schema.type)
    @property
    def default(self):
        return self.schema.default
    @property
    def order(self):
        return self.schema.order

########################### resolving types out of order in streaming input

class AvroPlaceholder(object):
    def __init__(self, original, forwardDeclarationParser):
        self.original = original
        self.forwardDeclarationParser = forwardDeclarationParser
        
    @property
    def avroType(self):
        return self.forwardDeclarationParser.lookup(self.original)

    def __eq__(self, other):
        if isinstance(other, AvroPlaceholder):
            return self.avroType == other.avroType
        elif isinstance(other, AvroType):
            return self.avroType == other
        else:
            return False

    def __hash__(self):
        return hash(self.avroType)

    def __repr__(self):
        if self.forwardDeclarationParser.contains(self.original):
            return repr(self.forwardDeclarationParser.lookup(self.original))
        else:
            return '{"type": "unknown"}'

    @property
    def parser(self):
        return self.forwardDeclarationParser

class AvroFilledPlaceholder(AvroPlaceholder):
    def __init__(self, avroType):
        self._avroType = avroType

    @property
    def avroType(self):
        return self._avroType

    def __repr__(self):
        return repr(self.avroType)

class ForwardDeclarationParser(object):
    def __init__(self):
        self.types = {}
        self.names = avro.schema.Names()
        self.lookupTable = {}

    def contains(self, original):
        return original in self.lookupTable

    def lookup(self, original):
        return self.lookupTable[original]

    @property
    def compiledTypes(self):
        return [x for x in self.lookupTable if isinstance(x, (AvroFixed, AvroRecord, AvroEnum))]

    def parse(self, jsonStrings):
        schemae = {}
        unresolvedSize = -1
        lastUnresolvedSize = -1
        errorMessages = {}

        while unresolvedSize != 0:
            for jsonString in jsonStrings:
                if jsonString not in schemae:
                    obj = json.loads(jsonString)

                    if isinstance(obj, basestring) and self.names.has_name(obj, None):
                        gotit = self.names.get_name(obj, None)
                        schemae[jsonString] = gotit
                    else:
                        oldnames = dict(self.names.names)

                        try:
                            gotit = avro.schema.make_avsc_object(obj, self.names)
                        except avro.schema.SchemaParseException as err:
                            self.names.names = oldnames
                            errorMessages[jsonString] = str(err)
                        else:
                            schemae[jsonString] = gotit

            unresolved = [x for x in jsonStrings if x not in schemae]
            unresolvedSize = len(unresolved)

            if unresolvedSize == lastUnresolvedSize:
                raise pfa.errors.SchemaParseException("Could not resolve the following types:\n    " +
                    "\n    ".join(["{} ({})".format(x, errorMessages[x]) for x in jsonStrings if x not in schemae]))
            else:
                lastUnresolvedSize = unresolvedSize

        result = dict((x, schemaToAvroType(schemae[x])) for x in jsonStrings)
        self.lookupTable.update(result)
        return result

    def getSchema(self, description):
        if self.names.has_name(description, None):
            return self.names.get_name(description, None)
        else:
            raise NotImplementedError   # straightforward to implement, but not needed yet...

    def getAvroType(self, description):
        schema = self.getSchema(description)
        if schema is None:
            return None
        else:
            return schemaToAvroType(schema)

class AvroTypeBuilder(object):
    def __init__(self):
        self.forwardDeclarationParser = ForwardDeclarationParser()
        self.originals = []

    def makePlaceholder(self, avroJsonString):
        self.originals.append(avroJsonString)
        return AvroPlaceholder(avroJsonString, self.forwardDeclarationParser)

    def resolveTypes(self):
        self.forwardDeclarationParser.parse(self.originals)
        self.originals = []

    def resolveOneType(self, avroJsonString):
        return ForwardDeclarationParser().parse([avroJsonString])[avroJsonString]
