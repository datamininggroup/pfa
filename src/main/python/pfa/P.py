#!/usr/bin/env python

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

class Pattern(object): pass

class Null(Pattern):
    def __repr__(self):
        return "P.Null()"

class Boolean(Pattern):
    def __repr__(self):
        return "P.Boolean()"

class Int(Pattern):
    def __repr__(self):
        return "P.Int()"

class Long(Pattern):
    def __repr__(self):
        return "P.Long()"

class Float(Pattern):
    def __repr__(self):
        return "P.Float()"

class Double(Pattern):
    def __repr__(self):
        return "P.Double()"

class Bytes(Pattern):
    def __repr__(self):
        return "P.Bytes()"

class String(Pattern):
    def __repr__(self):
        return "P.String()"

class Array(Pattern):
    def __init__(self, items):
        self._items = items
    @property
    def items(self):
        return self._items
    def __repr__(self):
        return "P.Array(" + repr(self.items) + ")"

class Map(Pattern):
    def __init__(self, values):
        self._values = values
    @property
    def values(self):
        return self._values
    def __repr__(self):
        return "P.Map(" + repr(self.values) + ")"

class Union(Pattern):
    def __init__(self, types):
        self._types = types
    @property
    def types(self):
        return self._types
    def __repr__(self):
        return "P.Union(" + repr(self.types) + ")"

class Fixed(Pattern):
    def __init__(self, size, fullName=None):
        self._size = size
        self._fullName = fullName
    @property
    def size(self):
        return self._size
    @property
    def fullName(self):
        return self._fullName
    def __repr__(self):
        return "P.Fixed(" + repr(self.size) + ", " + repr(self.fullName) + ")"

class Enum(Pattern):
    def __init__(self, symbols, fullName=None):
        self._symbols = symbols
        self._fullName = fullName
    @property
    def symbols(self):
        return self._symbols
    @property
    def fullName(self):
        return self._fullName
    def __repr__(self):
        return "P.Enum(" + repr(self.symbols) + ", " + repr(self.fullName) + ")"

class Record(Pattern):
    def __init__(self, fields, fullName=None):
        self._fields = fields
        self._fullName = fullName
    @property
    def fields(self):
        return self._fields
    @property
    def fullName(self):
        return self._fullName
    def __repr__(self):
        return "P.Record(" + repr(self.fields) + ", " + repr(self.fullName) + ")"

class Fcn(Pattern):
    def __init__(self, params, ret):
        self._params = params
        self._ret = ret
    @property
    def params(self):
        return self._params
    @property
    def ret(self):
        return self._ret
    def __repr__(self):
        return "P.Fcn(" + repr(self.params) + ", " + repr(self.ret) + ")"

class Wildcard(Pattern):
    def __init__(self, label, oneOf=None):
        self._label = label
        self._oneOf = oneOf
    @property
    def label(self):
        return self._label
    @property
    def oneOf(self):
        return self._oneOf
    def __repr__(self):
        return "P.Wildcard(" + repr(self.label) + ", " + repr(self.oneOf) + ")"

class WildRecord(Pattern):
    def __init__(self, label, minimalFields=None):
        self._label = label
        self._minimalFields = minimalFields
    @property
    def label(self):
        return self._label
    @property
    def minimalFields(self):
        return self._minimalFields
    def __repr__(self):
        return "P.WildRecord(" + repr(self.label) + ", " + repr(self.minimalFields) + ")"

def toType(pat):
    if isinstance(pat, Null): return AvroNull()
    elif isinstance(pat, Boolean): return AvroBoolean()
    elif isinstance(pat, Int): return AvroInt()
    elif isinstance(pat, Long): return AvroLong()
    elif isinstance(pat, Float): return AvroFloat()
    elif isinstance(pat, Double): return AvroDouble()
    elif isinstance(pat, Bytes): return AvroBytes()
    elif isinstance(pat, String): return AvroString()

    elif isinstance(pat, Array): return AvroArray(toType(pat.items))
    elif isinstance(pat, Map): return AvroMap(toType(pat.values))
    elif isinstance(pat, Union): return AvroUnion([toType(x) for x in pat.types])

    elif isinstance(pat, Fixed) and pat.fullName is not None:
        namebits = pat.fullName.split(".")
        if len(namebits) == 1:
            return AvroFixed(pat.size, namebits[-1], None)
        else:
            return AvroFixed(pat.size, namebits[-1], namebits[:-1])
    elif isinstance(pat, Fixed):
        return AvroFixed(pat.size)

    elif isinstance(pat, Enum) and pat.fullName is not None:
        namebits = pat.fullName.split(".")
        if len(namebits) == 1:
            return AvroEnum(pat.symbols, namebits[-1], None)
        else:
            return AvroEnum(pat.symbols, namebits[-1], namebits[:-1])
    elif isinstance(pat, Enum):
        return AvroEnum(pat.symbols)

    elif isinstance(pat, Record) and pat.fullName is not None:
        namebits = pat.fullName.split(".")
        if len(namebits) == 1:
            return AvroRecord([AvroField(k, toType(v)) for k, v in pat.fields.items()], namebits[-1], None)
        else:
            return AvroRecord([AvroField(k, toType(v)) for k, v in pat.fields.items()], namebits[-1], namebits[:-1])
    elif isinstance(pat, Record):
        return AvroRecord([AvroField(k, toType(v)) for k, v in pat.fields.items()])

    elif isinstance(pat, Fcn): return FcnType([toType(x) for x in pat.params()], toType(pat.ret()))

    else: raise Exception

def fromType(t):
    if isinstance(t, AvroNull): return Null()
    elif isinstance(t, AvroBoolean): return Boolean()
    elif isinstance(t, AvroInt): return Int()
    elif isinstance(t, AvroLong): return Long()
    elif isinstance(t, AvroFloat): return Float()
    elif isinstance(t, AvroDouble): return Double()
    elif isinstance(t, AvroBytes): return Bytes()
    elif isinstance(t, AvroString): return String()

    elif isinstance(t, AvroArray): return Array(fromType(t.items))
    elif isinstance(t, AvroMap): return Map(fromType(t.values))
    elif isinstance(t, AvroUnion): return Union([fromType(x) for x in t.types])

    elif isinstance(t, AvroFixed) and t.namespace is not None: return Fixed(t.size, t.namespace + "." + t.name)
    elif isinstance(t, AvroFixed): return Fixed(t.size, t.name)
    elif isinstance(t, AvroEnum) and t.namespace is not None: return Enum(t.symbols, t.namespace + "." + t.name)
    elif isinstance(t, AvroEnum): return Enum(t.symbols, t.name)
    elif isinstance(t, AvroRecord) and t.namespace is not None: return Record(dict((f.name, fromType(f.avroType)) for f in t.fields), t.namespace + "." + t.name)
    elif isinstance(t, AvroRecord): return Record(dict((f.name, fromType(f.avroType)) for f in t.fields), t.name)
        
    elif isinstance(t, FcnType): return Fcn([fromType(x) for x in t.params()], fromType(t.ret()))

def mustBeAvro(t):
    if not isinstance(t, AvroType):
        raise TypeError(repr(t) + " is not an Avro type")
    else:
        return t
