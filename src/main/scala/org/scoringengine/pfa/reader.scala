package org.scoringengine.pfa

import java.lang.StringBuilder

import scala.collection.mutable

import org.codehaus.jackson.JsonFactory
import org.codehaus.jackson.JsonLocation
import org.codehaus.jackson.JsonNode
import org.codehaus.jackson.JsonParseException
import org.codehaus.jackson.JsonParser
import org.codehaus.jackson.JsonToken
import org.codehaus.jackson.map.ObjectMapper

import org.scoringengine.pfa.ast.validSymbolName
import org.scoringengine.pfa.ast.validFunctionName
import org.scoringengine.pfa.ast.Ast
import org.scoringengine.pfa.ast.Method
import org.scoringengine.pfa.ast.EngineConfig
import org.scoringengine.pfa.ast.Cell
import org.scoringengine.pfa.ast.Pool
import org.scoringengine.pfa.ast.Argument
import org.scoringengine.pfa.ast.Expression
import org.scoringengine.pfa.ast.LiteralValue
import org.scoringengine.pfa.ast.FcnDef
import org.scoringengine.pfa.ast.FcnRef
import org.scoringengine.pfa.ast.Call
import org.scoringengine.pfa.ast.Ref
import org.scoringengine.pfa.ast.LiteralNull
import org.scoringengine.pfa.ast.LiteralBoolean
import org.scoringengine.pfa.ast.LiteralInt
import org.scoringengine.pfa.ast.LiteralLong
import org.scoringengine.pfa.ast.LiteralFloat
import org.scoringengine.pfa.ast.LiteralDouble
import org.scoringengine.pfa.ast.LiteralString
import org.scoringengine.pfa.ast.LiteralBase64
import org.scoringengine.pfa.ast.Literal
import org.scoringengine.pfa.ast.NewObject
import org.scoringengine.pfa.ast.NewArray
import org.scoringengine.pfa.ast.Do
import org.scoringengine.pfa.ast.Let
import org.scoringengine.pfa.ast.SetVar
import org.scoringengine.pfa.ast.AttrGet
import org.scoringengine.pfa.ast.AttrTo
import org.scoringengine.pfa.ast.CellGet
import org.scoringengine.pfa.ast.CellTo
import org.scoringengine.pfa.ast.PoolGet
import org.scoringengine.pfa.ast.PoolTo
import org.scoringengine.pfa.ast.If
import org.scoringengine.pfa.ast.Cond
import org.scoringengine.pfa.ast.While
import org.scoringengine.pfa.ast.DoUntil
import org.scoringengine.pfa.ast.For
import org.scoringengine.pfa.ast.Foreach
import org.scoringengine.pfa.ast.Forkeyval
import org.scoringengine.pfa.ast.CastCase
import org.scoringengine.pfa.ast.CastBlock
import org.scoringengine.pfa.ast.Upcast
import org.scoringengine.pfa.ast.Doc
import org.scoringengine.pfa.ast.Error
import org.scoringengine.pfa.ast.Log

import org.scoringengine.pfa.types.AvroConversions._
import org.scoringengine.pfa.types.AvroType
import org.scoringengine.pfa.types.AvroNumber
import org.scoringengine.pfa.types.AvroRaw
import org.scoringengine.pfa.types.AvroIdentifier
import org.scoringengine.pfa.types.AvroContainer
import org.scoringengine.pfa.types.AvroMapping
import org.scoringengine.pfa.types.AvroNull
import org.scoringengine.pfa.types.AvroBoolean
import org.scoringengine.pfa.types.AvroInt
import org.scoringengine.pfa.types.AvroLong
import org.scoringengine.pfa.types.AvroFloat
import org.scoringengine.pfa.types.AvroDouble
import org.scoringengine.pfa.types.AvroBytes
import org.scoringengine.pfa.types.AvroFixed
import org.scoringengine.pfa.types.AvroString
import org.scoringengine.pfa.types.AvroEnum
import org.scoringengine.pfa.types.AvroArray
import org.scoringengine.pfa.types.AvroMap
import org.scoringengine.pfa.types.AvroRecord
import org.scoringengine.pfa.types.AvroField
import org.scoringengine.pfa.types.AvroUnion
import org.scoringengine.pfa.types.AvroPlaceholder
import org.scoringengine.pfa.types.AvroTypeBuilder

import org.scoringengine.pfa.errors.PFASyntaxException
import org.scoringengine.pfa.util.escapeJson
import org.scoringengine.pfa.util.pos
import org.scoringengine.pfa.util.uniqueEngineName
import org.scoringengine.pfa.yaml.yamlToJson

package reader {
  object jsonToAst extends Function1[String, EngineConfig] {
    private val jsonFactory = new JsonFactory
    private val objectMapper = new ObjectMapper
    jsonFactory.setCodec(objectMapper)

    private val NumberPattern = "[0-9]+".r
    
    def apply(src: java.io.File): EngineConfig = parserToAst(jsonFactory.createJsonParser(src))
    def apply(src: java.io.InputStream): EngineConfig = parserToAst(jsonFactory.createJsonParser(src))
    def apply(src: String): EngineConfig = parserToAst(jsonFactory.createJsonParser(src))

    private def parserToAst(parser: JsonParser): EngineConfig = {
      val avroTypeBuilder = new AvroTypeBuilder
      val result =
        try {
          readEngineConfig(parser, parser.nextToken(), avroTypeBuilder)
        }
        finally {
          parser.close()
        }
      avroTypeBuilder.resolveTypes()
      result
    }

    def expr(src: String): Expression = {
      val parser = jsonFactory.createJsonParser(src)
      val avroTypeBuilder = new AvroTypeBuilder
      val result =
        try {
          readExpression(parser, parser.nextToken(), "<expr>", "", avroTypeBuilder)
        }
        finally {
          parser.close()
        }
      avroTypeBuilder.resolveTypes()
      result
    }

    def exprs(src: String): Seq[Expression] = {
      val parser = jsonFactory.createJsonParser(src)
      val avroTypeBuilder = new AvroTypeBuilder
      val result =
        try {
          readExpressionArray(parser, parser.nextToken(), "<exprs>", "", avroTypeBuilder)
        }
        finally {
          parser.close()
        }
      avroTypeBuilder.resolveTypes()
      result
    }

    def fcn(src: String): FcnDef = {
      val parser = jsonFactory.createJsonParser(src)
      val avroTypeBuilder = new AvroTypeBuilder
      val result =
        try {
          readFcnDef(parser, parser.nextToken(), "<fcn>", "", avroTypeBuilder)
        }
        finally {
          parser.close()
        }
      avroTypeBuilder.resolveTypes()
      result
    }

    private val tokenMessage = Map(
      JsonToken.END_ARRAY -> """end of array ("]" character)""",
      JsonToken.END_OBJECT -> """end of object ("}" character)""",
      JsonToken.FIELD_NAME -> """field name""",
      JsonToken.NOT_AVAILABLE -> """nothing""",
      JsonToken.START_ARRAY -> """start of array ("[" character)""",
      JsonToken.START_OBJECT -> """start of object ("{" character)""",
      JsonToken.VALUE_EMBEDDED_OBJECT -> """embedded object""",
      JsonToken.VALUE_FALSE -> """false""",
      JsonToken.VALUE_NULL -> """null""",
      JsonToken.VALUE_NUMBER_FLOAT -> """floating-point number""",
      JsonToken.VALUE_NUMBER_INT -> """integer""",
      JsonToken.VALUE_STRING -> """string""",
      JsonToken.VALUE_TRUE -> """true"""
    )

    private def jsonAt(parser: JsonParser): String =
      "JSON start line,col %d,%d".format(parser.getCurrentLocation.getLineNr, parser.getCurrentLocation.getColumnNr)

    private def readEngineConfig(parser: JsonParser, token: JsonToken, avroTypeBuilder: AvroTypeBuilder): EngineConfig = token match {
      case null => throw new PFASyntaxException("empty input", "", "")
      case JsonToken.START_OBJECT => {
        var _at = jsonAt(parser)

        val keys = mutable.Set[String]()
        var _name: String = null
        var _method: Method.Method = Method.MAP
        var _input: AvroPlaceholder = null
        var _output: AvroPlaceholder = null
        var _begin: Seq[Expression] = Nil
        var _action: Seq[Expression] = null
        var _end: Seq[Expression] = Nil
        var _fcns = Map[String, FcnDef]()
        var _zero: Option[String] = None
        var _cells = Map[String, Cell]()
        var _pools = Map[String, Pool]()
        var _randseed: Option[Long] = None
        var _doc: Option[String] = None
        var _metadata: Option[JsonNode] = None
        var _options = Map[String, JsonNode]()

        var subtoken = parser.nextToken()
        while (subtoken != JsonToken.END_OBJECT) {
          val key = parser.getCurrentName
          if (key == "@")
            _at = readString(parser, parser.nextToken(), key, _at)
          else {
            keys.add(key)
            key match {
              case "name" =>      _name = readString(parser, parser.nextToken(), key, _at)
              case "method" => readString(parser, parser.nextToken(), key, _at) match {
                case "map" =>     _method = Method.MAP
                case "emit" =>    _method = Method.EMIT
                case "fold" =>    _method = Method.FOLD
                case x => throw new PFASyntaxException("expected one of \"map\", \"emit\", \"fold\", not \"%s\"".format(x), key, _at)
              }
              case "input" =>     _input = readAvroPlaceholder(parser, parser.nextToken(), key, _at, avroTypeBuilder)
              case "output" =>    _output = readAvroPlaceholder(parser, parser.nextToken(), key, _at, avroTypeBuilder)
              case "begin" => parser.nextToken() match {
                case x @ JsonToken.START_ARRAY => _begin = readExpressionArray(parser, x, key, _at, avroTypeBuilder)
                case x => _begin = List(readExpression(parser, x, key, _at, avroTypeBuilder))
              }
              case "action" => parser.nextToken() match {
                case x @ JsonToken.START_ARRAY => _action = readExpressionArray(parser, x, key, _at, avroTypeBuilder)
                case x => _action = List(readExpression(parser, x, key, _at, avroTypeBuilder))
              }
              case "end" => parser.nextToken() match {
                case x @ JsonToken.START_ARRAY => _end = readExpressionArray(parser, x, key, _at, avroTypeBuilder)
                case x => _end = List(readExpression(parser, x, key, _at, avroTypeBuilder))
              }
              case "fcns" =>      _fcns = readFcnDefMap(parser, parser.nextToken(), key, _at, avroTypeBuilder)
              case "zero" =>      _zero = Some(readJsonToString(parser, parser.nextToken(), key, _at))
              case "cells" =>     _cells = readCells(parser, parser.nextToken(), key, _at, avroTypeBuilder)
              case "pools" =>     _pools = readPools(parser, parser.nextToken(), key, _at, avroTypeBuilder)
              case "randseed" =>  _randseed = Some(readLong(parser, parser.nextToken(), key, _at))
              case "doc" =>       _doc = Some(readString(parser, parser.nextToken(), key, _at))
              case "metadata" =>  _metadata = Some(readJsonNode(parser, parser.nextToken(), key, _at))
              case "options" =>   _options = readJsonNodeMap(parser, parser.nextToken(), key, _at)
              case x => throw new PFASyntaxException("unexpected top-level field: %s".format(x), "", _at)
            }
          }
          subtoken = parser.nextToken()
        }

        if (_name == null)
          _name = uniqueEngineName()

        if (_method == Method.FOLD  &&  !keys.contains("zero"))
          throw new PFASyntaxException("folding engines must include a \"zero\" to begin the calculation", "", _at)

        val required = Set("action", "input", "output")
        if ((keys intersect required) != required)
          throw new PFASyntaxException("missing top-level fields: %s".format((required diff keys).mkString(", ")), "", _at)
        else
          EngineConfig(_name, _method, _input, _output, _begin, _action, _end, _fcns, _zero, _cells, _pools, _randseed, _doc, _metadata, _options, Some(pos("", _at)))
      }
      case x => throw new PFASyntaxException("PFA engine must be a JSON object, not %s".format(tokenMessage.getOrElse(x, x.toString)), "", jsonAt(parser))
    }

    private def ingestJson(parser: JsonParser, token: JsonToken, dot: String, stringBuilder: StringBuilder): Unit = token match {
      case JsonToken.VALUE_NULL => stringBuilder.append("null")
      case JsonToken.VALUE_TRUE => stringBuilder.append("true")
      case JsonToken.VALUE_FALSE => stringBuilder.append("false")
      case JsonToken.VALUE_NUMBER_INT => stringBuilder.append(parser.getText)
      case JsonToken.VALUE_NUMBER_FLOAT => stringBuilder.append(parser.getText)
      case JsonToken.VALUE_STRING => stringBuilder.append("\"" + escapeJson(parser.getText) + "\"")
      case JsonToken.START_ARRAY => {
        stringBuilder.append("[")
        var first = true
        var subtoken = parser.nextToken()
        while (subtoken != JsonToken.END_ARRAY) {
          if (first)
            first = false
          else
            stringBuilder.append(",")
          ingestJson(parser, subtoken, dot, stringBuilder)
          subtoken = parser.nextToken()
        }
        stringBuilder.append("]")
      }
      case JsonToken.START_OBJECT => {
        stringBuilder.append("{")
        var first = true
        var subtoken = parser.nextToken()
        while (subtoken != JsonToken.END_OBJECT) {
          if (parser.getCurrentName == "@")
            ingestJson(parser, parser.nextToken(), dot, new StringBuilder)   // skip it
          else {
            if (first)
              first = false
            else
              stringBuilder.append(",")
            stringBuilder.append("\"" + escapeJson(parser.getCurrentName) + "\":")
            ingestJson(parser, parser.nextToken(), dot, stringBuilder)
          }
          subtoken = parser.nextToken()
        }
        stringBuilder.append("}")
      }
      case _ =>
    }

    private def readJsonToString(parser: JsonParser, token: JsonToken, dot: String, at: String): String = {
      val stringBuilder = new StringBuilder
      ingestJson(parser, token, dot, stringBuilder)
      stringBuilder.toString
    }

    private def readJsonNode(parser: JsonParser, token: JsonToken, dot: String, at: String): JsonNode = {
      val stringBuilder = new StringBuilder
      ingestJson(parser, token, dot, stringBuilder)
      val secondParser = jsonFactory.createJsonParser(stringBuilder.toString)
      secondParser.readValueAsTree
    }

    private def readAvroPlaceholder(parser: JsonParser, token: JsonToken, dot: String, at: String, avroTypeBuilder: AvroTypeBuilder): AvroPlaceholder = {
      val stringBuilder = new StringBuilder
      ingestJson(parser, token, dot, stringBuilder)
      avroTypeBuilder.makePlaceholder(stringBuilder.toString)
    }

    private def readJsonNodeMap(parser: JsonParser, token: JsonToken, dot: String, at: String): Map[String, JsonNode] = token match {
      case JsonToken.START_OBJECT => {
        var items = List[(String, JsonNode)]()
        var subtoken = parser.nextToken()
        while (subtoken != JsonToken.END_OBJECT) {
          val key = parser.getCurrentName
          if (key != "@")
            items = (key, readJsonNode(parser, parser.nextToken(), dot + "." + key, at)) :: items
          subtoken = parser.nextToken()
        }
        items.toMap
      }
      case x => throw new PFASyntaxException("expected map of JSON objects, found %s".format(tokenMessage.getOrElse(x, x.toString)), dot, at)
    }

    private def readJsonToStringMap(parser: JsonParser, token: JsonToken, dot: String, at: String): Map[String, String] = token match {
      case JsonToken.START_OBJECT => {
        var items = List[(String, String)]()
        var subtoken = parser.nextToken()
        while (subtoken != JsonToken.END_OBJECT) {
          val key = parser.getCurrentName
          if (key != "@")
            items = (key, readJsonToString(parser, parser.nextToken(), dot + "." + key, at)) :: items
          subtoken = parser.nextToken()
        }
        items.toMap
      }
      case x => throw new PFASyntaxException("expected map of JSON objects, found %s".format(tokenMessage.getOrElse(x, x.toString)), dot, at)
    }

    private def readBoolean(parser: JsonParser, token: JsonToken, dot: String, at: String): Boolean = token match {
      case JsonToken.VALUE_TRUE => true
      case JsonToken.VALUE_FALSE => false
      case x => throw new PFASyntaxException("expected boolean, found %s".format(tokenMessage.getOrElse(x, x.toString)), dot, at)
    }

    private def readInt(parser: JsonParser, token: JsonToken, dot: String, at: String): Int = token match {
      case JsonToken.VALUE_NUMBER_INT => parser.getIntValue
      case x => throw new PFASyntaxException("expected whole number (32-bit precision), found %s".format(tokenMessage.getOrElse(x, x.toString)), dot, at)
    }

    private def readLong(parser: JsonParser, token: JsonToken, dot: String, at: String): Long = token match {
      case JsonToken.VALUE_NUMBER_INT => parser.getLongValue
      case x => throw new PFASyntaxException("expected whole number, found %s".format(tokenMessage.getOrElse(x, x.toString)), dot, at)
    }

    private def readFloat(parser: JsonParser, token: JsonToken, dot: String, at: String): Float = token match {
      case JsonToken.VALUE_NUMBER_INT | JsonToken.VALUE_NUMBER_FLOAT => parser.getFloatValue
      case x => throw new PFASyntaxException("expected number (32-bit precision), found %s".format(tokenMessage.getOrElse(x, x.toString)), dot, at)
    }

    private def readDouble(parser: JsonParser, token: JsonToken, dot: String, at: String): Double = token match {
      case JsonToken.VALUE_NUMBER_INT | JsonToken.VALUE_NUMBER_FLOAT => parser.getDoubleValue
      case x => throw new PFASyntaxException("expected number, found %s".format(tokenMessage.getOrElse(x, x.toString)), dot, at)
    }

    private def readStringArray(parser: JsonParser, token: JsonToken, dot: String, at: String): Seq[String] = token match {
      case JsonToken.START_ARRAY => {
        var items = List[String]()
        var subtoken = parser.nextToken()
        var counter = 0
        while (subtoken != JsonToken.END_ARRAY) {
          items = readString(parser, subtoken, dot + ".%d".format(counter), at) :: items
          subtoken = parser.nextToken()
        }
        items.reverse
      }
      case x => throw new PFASyntaxException("expected array of strings, found %s".format(tokenMessage.getOrElse(x, x.toString)), dot, at)
    }

    private def readString(parser: JsonParser, token: JsonToken, dot: String, at: String): String = token match {
      case JsonToken.VALUE_STRING => parser.getText
      case x => throw new PFASyntaxException("expected string, found %s".format(tokenMessage.getOrElse(x, x.toString)), dot, at)
    }

    private def readBase64(parser: JsonParser, token: JsonToken, dot: String, at: String): Array[Byte] = token match {
      case JsonToken.VALUE_STRING => try {
        parser.getBinaryValue
      }
      catch {
        case err: JsonParseException => throw new PFASyntaxException("expected base64 data, found \"%s\"".format(parser.getText), dot, at)
      }
      case x => throw new PFASyntaxException("expected base64 data, found %s".format(tokenMessage.getOrElse(x, x.toString)), dot, at)
    }

    private def readExpressionArray(parser: JsonParser, token: JsonToken, dot: String, at: String, avroTypeBuilder: AvroTypeBuilder): Seq[Expression] = token match {
      case JsonToken.START_ARRAY => {
        var items = List[Expression]()
        var subtoken = parser.nextToken()
        var counter = 0
        while (subtoken != JsonToken.END_ARRAY) {
          items = readExpression(parser, subtoken, dot + ".%d".format(counter), at, avroTypeBuilder) :: items
          subtoken = parser.nextToken()
        }
        items.reverse
      }
      case x => throw new PFASyntaxException("expected array of expressions, found %s".format(tokenMessage.getOrElse(x, x.toString)), dot, at)
    }

    private def readExpressionMap(parser: JsonParser, token: JsonToken, dot: String, at: String, avroTypeBuilder: AvroTypeBuilder): Map[String, Expression] = token match {
      case JsonToken.START_OBJECT => {
        var _at = jsonAt(parser)

        var items = List[(String, Expression)]()
        var subtoken = parser.nextToken()
        while (subtoken != JsonToken.END_OBJECT) {
          val key = parser.getCurrentName
          if (key == "@")
            _at = readString(parser, parser.nextToken(), dot + "." + key, at)
          else if (validSymbolName(key))
            items = (key, readExpression(parser, parser.nextToken(), dot + "." + key, _at, avroTypeBuilder)) :: items
          else
            throw new PFASyntaxException("\"%s\" is not a valid symbol name".format(key), dot, at)
          subtoken = parser.nextToken()
        }
        items.toMap
      }
      case x => throw new PFASyntaxException("expected map of expressions, found %s".format(tokenMessage.getOrElse(x, x.toString)), dot, at)
    }

    private def readCastCaseArray(parser: JsonParser, token: JsonToken, dot: String, at: String, avroTypeBuilder: AvroTypeBuilder): Seq[CastCase] = token match {
      case JsonToken.START_ARRAY => {
        var items = List[CastCase]()
        var subtoken = parser.nextToken()
        var counter = 0
        while (subtoken != JsonToken.END_ARRAY) {
          items = readCastCase(parser, subtoken, dot + ".%d".format(counter), at, avroTypeBuilder) :: items
          subtoken = parser.nextToken()
        }
        items.reverse
      }
      case x => throw new PFASyntaxException("expected array of cast-cases, found %s".format(tokenMessage.getOrElse(x, x.toString)), dot, at)
    }

    private def readCastCase(parser: JsonParser, token: JsonToken, dot: String, at: String, avroTypeBuilder: AvroTypeBuilder): CastCase = token match {
      case JsonToken.START_OBJECT => {
        var _at = jsonAt(parser)

        val keys = mutable.Set[String]()
        var _as: AvroPlaceholder = null
        var _named: String = null
        var _body: Seq[Expression] = null

        var subtoken = parser.nextToken()
        while (subtoken != JsonToken.END_OBJECT) {
          val key = parser.getCurrentName
          if (key == "@")
            _at = readString(parser, parser.nextToken(), dot + "." + key, at)
          else {
            keys.add(key)
            key match {
              case "as" =>    _as = readAvroPlaceholder(parser, parser.nextToken(), dot + "." + key, _at, avroTypeBuilder)
              case "named" => _named = readString(parser, parser.nextToken(), dot + "." + key, _at)
              case "do" => parser.nextToken() match {
                case x @ JsonToken.START_ARRAY => _body = readExpressionArray(parser, x, dot + "." + key, _at, avroTypeBuilder)
                case x => _body = List(readExpression(parser, x, dot + "." + key, _at, avroTypeBuilder))
              }
              case x => throw new PFASyntaxException("unexpected field in cast-case: %s".format(x), dot, _at)
            }
          }
          subtoken = parser.nextToken()
        }

        if (_named != null  &&  !validSymbolName(_named))
          throw new PFASyntaxException("\"%s\" is not a valid symbol name".format(_named), dot, at)

        val required = Set("as", "named", "do")
        if (keys != required)
          throw new PFASyntaxException("wrong set of fields for a cast-case: %s".format(keys.mkString(", ")), dot, _at)
        else
          CastCase(_as, _named, _body, Some(pos(dot, _at)))
      }
      case x => throw new PFASyntaxException("expected cast-case, found %s".format(tokenMessage.getOrElse(x, x.toString)), dot, at)
    }

    private def readExpression(parser: JsonParser, token: JsonToken, dot: String, at: String, avroTypeBuilder: AvroTypeBuilder): Expression =
      readArgument(parser, token, dot, at, avroTypeBuilder) match {
        case expr: Expression => expr
        case arg: Argument => throw new PFASyntaxException("argument appears outside of argument list", dot, at)
      }

    private def readArgumentArray(parser: JsonParser, token: JsonToken, dot: String, at: String, avroTypeBuilder: AvroTypeBuilder): Seq[Argument] = token match {
      case JsonToken.START_ARRAY => {
        var items = List[Argument]()
        var subtoken = parser.nextToken()
        var counter = 0
        while (subtoken != JsonToken.END_ARRAY) {
          items = readArgument(parser, subtoken, dot + ".%d".format(counter), at, avroTypeBuilder) :: items
          subtoken = parser.nextToken()
        }
        items.reverse
      }
      case x => throw new PFASyntaxException("expected array of arguments, found %s".format(tokenMessage.getOrElse(x, x.toString)), dot, at)
    }

    private def readArgument(parser: JsonParser, token: JsonToken, dot: String, at: String, avroTypeBuilder: AvroTypeBuilder): Argument = token match {
      case JsonToken.VALUE_NULL => LiteralNull(Some(pos(dot, at)))
      case JsonToken.VALUE_TRUE => LiteralBoolean(true, Some(pos(dot, at)))
      case JsonToken.VALUE_FALSE => LiteralBoolean(false, Some(pos(dot, at)))
      case JsonToken.VALUE_NUMBER_INT => {
        val value = parser.getBigIntegerValue
        if (value.compareTo(java.math.BigInteger.valueOf(java.lang.Integer.MIN_VALUE)) >= 0  &&  value.compareTo(java.math.BigInteger.valueOf(java.lang.Integer.MAX_VALUE)) <= 0)
          LiteralInt(value.intValue, Some(pos(dot, at)))
        else if (value.compareTo(java.math.BigInteger.valueOf(java.lang.Long.MIN_VALUE)) >= 0  &&  value.compareTo(java.math.BigInteger.valueOf(java.lang.Long.MAX_VALUE)) <= 0)
          LiteralLong(parser.getLongValue, Some(pos(dot, at)))
        else
          throw new PFASyntaxException("integer out of range: " + value.toString, dot, at)
      }
      case JsonToken.VALUE_NUMBER_FLOAT => LiteralDouble(parser.getDoubleValue, Some(pos(dot, at)))
      case JsonToken.VALUE_STRING => parser.getText.split("""\.""").toList match {
        case item :: Nil =>
          if (validSymbolName(item))
            Ref(item, Some(pos(dot, at)))
          else
            throw new PFASyntaxException("\"%s\" is not a valid symbol name".format(item), dot, at)

        case base :: path =>
          if (validSymbolName(base))
            AttrGet(base, path.map(x => x match {
              case NumberPattern() => LiteralInt(x.toInt, Some(pos(dot, at)))
              case _ => LiteralString(x, Some(pos(dot, at)))
            }), Some(pos(dot, at)))
          else
            throw new PFASyntaxException("\"%s\" is not a valid symbol name".format(base), dot, at)
      }

      case JsonToken.START_ARRAY => {
        val result: String =
          if (parser.nextToken() == JsonToken.VALUE_STRING) {
            val str = parser.getText
            if (parser.nextToken() == JsonToken.END_ARRAY)
              str
            else
              null
          }
          else
            null
        if (result == null)
          throw new PFASyntaxException("expecting expression, which may be [\"string\"], but no other array can be used as an expression", dot, at)
        LiteralString(result, Some(pos(dot, at)))
      }

      case JsonToken.START_OBJECT => {
        var _at = jsonAt(parser)

        val keys = mutable.Set[String]()

        var _int: Int = 0
        var _long: Long = 0L
        var _float: Float = 0.0F
        var _double: Double = 0.0
        var _string: String = null
        var _bytes: Array[Byte] = null
        var _avroType: AvroPlaceholder = null
        var _value: String = null

        var _let: Map[String, Expression] = null
        var _set: Map[String, Expression] = null
        var _forlet: Map[String, Expression] = null
        var _forstep: Map[String, Expression] = null
        
        var _body: Seq[Expression] = null
        var _thenClause: Seq[Expression] = null
        var _elseClause: Seq[Expression] = null
        var _log: Seq[Expression] = null
        var _path: Seq[Expression] = Nil

        var _ifPredicate: Expression = null
        var _whilePredicate: Expression = null
        var _until: Expression = null

        var _cond: Seq[Expression] = null
        var _cases: Seq[CastCase] = null

        var _foreach: String = null
        var _forkey: String = null
        var _forval: String = null
        var _fcnref: String = null
        var _attr: String = null
        var _cell: String = null
        var _pool: String = null

        var _in: Expression = null
        var _cast: Expression = null
        var _upcast: Expression = null
        var _init: Option[Expression] = None

        var _seq: Boolean = false
        var _partial: Boolean = false

        var _doc: String = null
        var _error: String = null
        var _code: Int = 0
        var _namespace: String = null

        var _newObject: Map[String, Expression] = null
        var _newArray: Seq[Expression] = null

        var _params: Seq[(String, AvroPlaceholder)] = null
        var _ret: AvroPlaceholder = null
        var _as: AvroPlaceholder = null

        var _callName: String = null
        var _callArgs: Seq[Argument] = null
        var _to: Argument = null

        var subtoken = parser.nextToken()
        while (subtoken != JsonToken.END_OBJECT) {
          val key = parser.getCurrentName
          if (key == "@")
            _at = readString(parser, parser.nextToken(), dot + "." + key, at)
          else {
            keys.add(key)
            key match {
              case "int" =>       _int = readInt(parser, parser.nextToken(), dot + "." + key, _at)
              case "long" =>      _long = readLong(parser, parser.nextToken(), dot + "." + key, _at)
              case "float" =>     _float = readFloat(parser, parser.nextToken(), dot + "." + key, _at)
              case "double" =>    _double = readDouble(parser, parser.nextToken(), dot + "." + key, _at)
              case "string" =>    _string = readString(parser, parser.nextToken(), dot + "." + key, _at)
              case "base64" =>    _bytes = readBase64(parser, parser.nextToken(), dot + "." + key, _at)
              case "type" =>      _avroType = readAvroPlaceholder(parser, parser.nextToken(), dot + "." + key, _at, avroTypeBuilder)
              case "value" =>     _value = readJsonToString(parser, parser.nextToken(), dot + "." + key, _at)

              case "let" =>       _let = readExpressionMap(parser, parser.nextToken(), dot + "." + key, _at, avroTypeBuilder)
              case "set" =>       _set = readExpressionMap(parser, parser.nextToken(), dot + "." + key, _at, avroTypeBuilder)
              case "for" =>       _forlet = readExpressionMap(parser, parser.nextToken(), dot + "." + key, _at, avroTypeBuilder)
              case "step" =>      _forstep = readExpressionMap(parser, parser.nextToken(), dot + "." + key, _at, avroTypeBuilder)

              case "do" => parser.nextToken() match {
                case x @ JsonToken.START_ARRAY => _body = readExpressionArray(parser, x, dot + "." + key, _at, avroTypeBuilder)
                case x => _body = List(readExpression(parser, x, dot + "." + key, _at, avroTypeBuilder))
              }
              case "then" => parser.nextToken() match {
                case x @ JsonToken.START_ARRAY => _thenClause = readExpressionArray(parser, x, dot + "." + key, _at, avroTypeBuilder)
                case x => _thenClause = List(readExpression(parser, x, dot + "." + key, _at, avroTypeBuilder))
              }
              case "else" => parser.nextToken() match {
                case x @ JsonToken.START_ARRAY => _elseClause = readExpressionArray(parser, x, dot + "." + key, _at, avroTypeBuilder)
                case x => _elseClause = List(readExpression(parser, x, dot + "." + key, _at, avroTypeBuilder))
              }
              case "log" => parser.nextToken() match {
                case x @ JsonToken.START_ARRAY => _log = readExpressionArray(parser, x, dot + "." + key, _at, avroTypeBuilder)
                case x => _log = List(readExpression(parser, x, dot + "." + key, _at, avroTypeBuilder))
              }
              case "path" =>      _path = readExpressionArray(parser, parser.nextToken(), dot + "." + key, _at, avroTypeBuilder)

              case "if" =>        _ifPredicate = readExpression(parser, parser.nextToken(), dot + "." + key, _at, avroTypeBuilder)
              case "while" =>     _whilePredicate = readExpression(parser, parser.nextToken(), dot + "." + key, _at, avroTypeBuilder)
              case "until" =>     _until = readExpression(parser, parser.nextToken(), dot + "." + key, _at, avroTypeBuilder)

              case "cond" => {
                _cond = readExpressionArray(parser, parser.nextToken(), dot + "." + key, _at, avroTypeBuilder)
                if (!_cond.forall({case If(_, _, None, _) => true; case _ => false}))
                  throw new PFASyntaxException("cond expression must only contain else-less if expressions", dot, _at)
              }

              case "cases" =>     _cases = readCastCaseArray(parser, parser.nextToken(), dot + "." + key, _at, avroTypeBuilder)

              case "foreach" =>   _foreach = readString(parser, parser.nextToken(), dot + "." + key, _at)
              case "forkey" =>    _forkey = readString(parser, parser.nextToken(), dot + "." + key, _at)
              case "forval" =>    _forval = readString(parser, parser.nextToken(), dot + "." + key, _at)
              case "fcnref" =>    _fcnref = readString(parser, parser.nextToken(), dot + "." + key, _at)
              case "attr" =>      _attr = readString(parser, parser.nextToken(), dot + "." + key, _at)
              case "cell" =>      _cell = readString(parser, parser.nextToken(), dot + "." + key, _at)
              case "pool" =>      _pool = readString(parser, parser.nextToken(), dot + "." + key, _at)

              case "in" =>        _in = readExpression(parser, parser.nextToken(), dot + "." + key, _at, avroTypeBuilder)
              case "cast" =>      _cast = readExpression(parser, parser.nextToken(), dot + "." + key, _at, avroTypeBuilder)
              case "upcast" =>    _upcast = readExpression(parser, parser.nextToken(), dot + "." + key, _at, avroTypeBuilder)
              case "init" =>      _init = Some(readExpression(parser, parser.nextToken(), dot + "." + key, _at, avroTypeBuilder))

              case "seq" =>       _seq = readBoolean(parser, parser.nextToken(), dot + "." + key, _at)
              case "partial" =>   _partial = readBoolean(parser, parser.nextToken(), dot + "." + key, _at)

              case "doc" =>       _doc = readString(parser, parser.nextToken(), dot + "." + key, _at)
              case "error" =>     _error = readString(parser, parser.nextToken(), dot + "." + key, _at)
              case "code" =>      _code = readInt(parser, parser.nextToken(), dot + "." + key, _at)
              case "namespace" => _namespace = readString(parser, parser.nextToken(), dot + "." + key, _at)

              case "new" => parser.nextToken() match {
                case x @ JsonToken.START_OBJECT => _newObject = readExpressionMap(parser, x, dot + "." + key, _at, avroTypeBuilder);  _newArray = null
                case x @ JsonToken.START_ARRAY => _newArray = readExpressionArray(parser, x, dot + "." + key, _at, avroTypeBuilder);  _newObject = null
                case x => throw new PFASyntaxException("\"new\" must be an object (map, record) or an array, not " + x.toString, dot, at)
              }

              case "params" =>    _params = readParams(parser, parser.nextToken(), dot + "." + key, _at, avroTypeBuilder)
              case "ret" =>       _ret = readAvroPlaceholder(parser, parser.nextToken(), dot + "." + key, _at, avroTypeBuilder)
              case "as" =>        _as = readAvroPlaceholder(parser, parser.nextToken(), dot + "." + key, _at, avroTypeBuilder)

              case "to" =>        _to = readArgument(parser, parser.nextToken(), dot + "." + key, _at, avroTypeBuilder)

              case x => {
                _callName = x
                parser.nextToken() match {
                  case x @ JsonToken.START_ARRAY => _callArgs = readArgumentArray(parser, x, dot + "." + key, _at, avroTypeBuilder)
                  case x => _callArgs = List(readArgument(parser, x, dot + "." + key, _at, avroTypeBuilder))
                }
              }
            }
          }
          subtoken = parser.nextToken()
        }

        if (keys.contains("foreach")  &&  !validSymbolName(_foreach))
          throw new PFASyntaxException("\"%s\" is not a valid symbol name".format(_foreach), dot, at)
        if (keys.contains("forkey")  &&  !validSymbolName(_forkey))
          throw new PFASyntaxException("\"%s\" is not a valid symbol name".format(_forkey), dot, at)
        if (keys.contains("forval")  &&  !validSymbolName(_forval))
          throw new PFASyntaxException("\"%s\" is not a valid symbol name".format(_forval), dot, at)
        if (keys.contains("fcnref")  &&  !validFunctionName(_fcnref))
          throw new PFASyntaxException("\"%s\" is not a valid function name".format(_fcnref), dot, at)

        if (keys == Set("int"))                                      LiteralInt(_int, Some(pos(dot, _at)))
        else if (keys == Set("long"))                                LiteralLong(_long, Some(pos(dot, _at)))
        else if (keys == Set("float"))                               LiteralFloat(_float, Some(pos(dot, _at)))
        else if (keys == Set("double"))                              LiteralDouble(_double, Some(pos(dot, _at)))
        else if (keys == Set("string"))                              LiteralString(_string, Some(pos(dot, _at)))
        else if (keys == Set("base64"))                              LiteralBase64(_bytes, Some(pos(dot, _at)))
        else if (keys == Set("type", "value"))                       Literal(_avroType, _value, Some(pos(dot, _at)))

        else if (keys == Set("new", "type")  &&  _newObject != null) NewObject(_newObject, _avroType, avroTypeBuilder, Some(pos(dot, _at)))
        else if (keys == Set("new", "type")  &&  _newArray != null)  NewArray(_newArray, _avroType, avroTypeBuilder, Some(pos(dot, _at)))

        else if (keys == Set("do"))                                  Do(_body, Some(pos(dot, _at)))
        else if (keys == Set("let"))                                 Let(_let, Some(pos(dot, _at)))
        else if (keys == Set("set"))                                 SetVar(_set, Some(pos(dot, _at)))

        else if (keys == Set("attr", "path"))                        AttrGet(_attr, _path, Some(pos(dot, _at)))
        else if (keys == Set("attr", "path", "to"))                  AttrTo(_attr, _path, _to, Some(pos(dot, _at)))
        else if (keys == Set("cell")  ||
                 keys == Set("cell", "path"))                        CellGet(_cell, _path, Some(pos(dot, _at)))
        else if (keys == Set("cell", "to")  ||
                 keys == Set("cell", "path", "to"))                  CellTo(_cell, _path, _to, Some(pos(dot, _at)))
        else if (keys == Set("pool", "path"))                        PoolGet(_pool, _path, Some(pos(dot, _at)))
        else if (keys == Set("pool", "path", "to")  ||
                 keys == Set("pool", "path", "to", "init"))          PoolTo(_pool, _path, _to, _init, Some(pos(dot, _at)))

        else if (keys == Set("if", "then"))                          If(_ifPredicate, _thenClause, None, Some(pos(dot, _at)))
        else if (keys == Set("if", "then", "else"))                  If(_ifPredicate, _thenClause, Some(_elseClause), Some(pos(dot, _at)))
        else if (keys == Set("cond"))                                Cond(_cond.map(_.asInstanceOf[If]), None, Some(pos(dot, _at)))
        else if (keys == Set("cond", "else"))                        Cond(_cond.map(_.asInstanceOf[If]), Some(_elseClause), Some(pos(dot, _at)))

        else if (keys == Set("while", "do"))                         While(_whilePredicate, _body, Some(pos(dot, _at)))
        else if (keys == Set("do", "until"))                         DoUntil(_body, _until, Some(pos(dot, _at)))
        else if (keys == Set("for", "until", "step", "do"))          For(_forlet, _until, _forstep, _body, Some(pos(dot, _at)))
        else if (keys == Set("foreach", "in", "do")  ||
                 keys == Set("foreach", "in", "do", "seq"))          Foreach(_foreach, _in, _body, _seq, Some(pos(dot, _at)))
        else if (keys == Set("forkey", "forval", "in", "do"))        Forkeyval(_forkey, _forval, _in, _body, Some(pos(dot, _at)))

        else if (keys == Set("cast", "cases")  ||
                 keys == Set("cast", "cases", "partial"))            CastBlock(_cast, _cases, _partial, Some(pos(dot, _at)))
        else if (keys == Set("upcast", "as"))                        Upcast(_upcast, _as, Some(pos(dot, _at)))

        else if (keys == Set("doc"))                                 Doc(_doc, Some(pos(dot, _at)))

        else if (keys == Set("error"))                               Error(_error, None, Some(pos(dot, _at)))
        else if (keys == Set("error", "code"))                       Error(_error, Some(_code), Some(pos(dot, _at)))
        else if (keys == Set("log"))                                 Log(_log, None, Some(pos(dot, _at)))
        else if (keys == Set("log", "namespace"))                    Log(_log, Some(_namespace), Some(pos(dot, _at)))

        // FcnDef and FcnRef can only be arguments, not expressions
        else if (keys == Set("params", "ret", "do"))                 FcnDef(_params, _ret, _body, Some(pos(dot, _at)))
        else if (keys == Set("fcnref"))                              FcnRef(_fcnref, Some(pos(dot, _at)))

        // function call is anything else
        else if (keys.size == 1  &&
                 !Set("as", "base64", "cases", "cast", "cell", "code", "cond", "do", "doc", "double", "else", "error", "fcnref",
                      "float", "for", "foreach", "forkey", "forval", "if", "in", "init", "int", "let", "log", "long",
                      "namespace", "new", "params", "partial", "path", "pool", "ret", "seq", "set", "step", "string", "then",
                      "to", "type", "upcast", "until", "value", "while").contains(keys.head))
                                                                     Call(_callName, _callArgs, Some(pos(dot, _at)))

        else throw new PFASyntaxException("not enough arguments for special form: %s".format(keys.mkString(" ")), dot, _at)
      }
      case x => throw new PFASyntaxException("expected expression, found %s".format(tokenMessage.getOrElse(x, x.toString)), dot, at)
    }

    private def readFcnDefMap(parser: JsonParser, token: JsonToken, dot: String, at: String, avroTypeBuilder: AvroTypeBuilder): Map[String, FcnDef] = token match {
      case JsonToken.START_OBJECT => {
        var _at = jsonAt(parser)

        var items = List[(String, FcnDef)]()
        var subtoken = parser.nextToken()
        while (subtoken != JsonToken.END_OBJECT) {
          val key = parser.getCurrentName
          if (key == "@")
            _at = readString(parser, parser.nextToken(), dot + "." + key, at)
          else if (validFunctionName(key))
            items = (key, readFcnDef(parser, parser.nextToken(), dot + "." + key, _at, avroTypeBuilder)) :: items
          else
            throw new PFASyntaxException("\"%s\" is not a valid function name".format(key), dot, at)
          subtoken = parser.nextToken()
        }
        items.toMap
      }
      case x => throw new PFASyntaxException("expected map of function definitions, found %s".format(tokenMessage.getOrElse(x, x.toString)), dot, at)
    }

    private def readFcnDef(parser: JsonParser, token: JsonToken, dot: String, at: String, avroTypeBuilder: AvroTypeBuilder): FcnDef = token match {
      case JsonToken.START_OBJECT => {
        var _at = jsonAt(parser)

        val keys = mutable.Set[String]()
        var _params: Seq[(String, AvroPlaceholder)] = null
        var _ret: AvroPlaceholder = null
        var _body: Seq[Expression] = null

        var subtoken = parser.nextToken()
        while (subtoken != JsonToken.END_OBJECT) {
          val key = parser.getCurrentName
          if (key == "@")
            _at = readString(parser, parser.nextToken(), dot + "." + key, at)
          else {
            keys.add(key)
            key match {
              case "params" => _params = readParams(parser, parser.nextToken(), dot + "." + key, _at, avroTypeBuilder)
              case "ret" =>    _ret = readAvroPlaceholder(parser, parser.nextToken(), dot + "." + key, _at, avroTypeBuilder)
              case "do" => parser.nextToken() match {
                case x @ JsonToken.START_ARRAY => _body = readExpressionArray(parser, x, dot + "." + key, _at, avroTypeBuilder)
                case x => _body = List(readExpression(parser, x, dot + "." + key, _at, avroTypeBuilder))
              }
              case x => throw new PFASyntaxException("unexpected field in function definition: %s".format(x), dot, _at)
            }
          }
          subtoken = parser.nextToken()
        }

        val required = Set("params", "ret", "do")
        if (keys != required)
          throw new PFASyntaxException("wrong set of fields for a function definition: %s".format(keys.mkString(", ")), dot, _at)
        else
          FcnDef(_params, _ret, _body, Some(pos(dot, _at)))
      }
      case x => throw new PFASyntaxException("expected function definition, found %s".format(tokenMessage.getOrElse(x, x.toString)), dot, at)
    }

    private def readParams(parser: JsonParser, token: JsonToken, dot: String, at: String, avroTypeBuilder: AvroTypeBuilder): Seq[(String, AvroPlaceholder)] = token match {
      case JsonToken.START_ARRAY => {
        var items = List[(String, AvroPlaceholder)]()
        var subtoken = parser.nextToken()
        var counter = 0
        while (subtoken != JsonToken.END_ARRAY) {
          items = readParam(parser, subtoken, dot + ".%d".format(counter), at, avroTypeBuilder) :: items
          subtoken = parser.nextToken()
        }
        items.reverse
      }
      case x => throw new PFASyntaxException("expected array of function parameters, found %s".format(tokenMessage.getOrElse(x, x.toString)), dot, at)
    }

    private def readParam(parser: JsonParser, token: JsonToken, dot: String, at: String, avroTypeBuilder: AvroTypeBuilder): (String, AvroPlaceholder) = token match {
      case JsonToken.START_OBJECT => {
        var _at = jsonAt(parser)

        var items = List[(String, AvroPlaceholder)]()
        var subtoken = parser.nextToken()
        while (subtoken != JsonToken.END_OBJECT) {
          val key = parser.getCurrentName
          if (key == "@")
            _at = readString(parser, parser.nextToken(), dot + "." + key, at)
          else if (validSymbolName(key))
            items = (key, readAvroPlaceholder(parser, parser.nextToken(), dot + "." + key, _at, avroTypeBuilder)) :: items
          else
            throw new PFASyntaxException("\"%s\" is not a valid symbol name".format(key), dot, at)
          subtoken = parser.nextToken()
        }

        if (items.size == 1)
          items(0)
        else
          throw new PFASyntaxException("function parameter name-type map should have only one pair", dot, _at)
      }
      case x => throw new PFASyntaxException("expected function parameter name-type singleton map, found %s".format(tokenMessage.getOrElse(x, x.toString)), dot, at)
    }

    private def readCells(parser: JsonParser, token: JsonToken, dot: String, at: String, avroTypeBuilder: AvroTypeBuilder): Map[String, Cell] = token match {
      case JsonToken.START_OBJECT => {
        var _at = jsonAt(parser)

        var items = List[(String, Cell)]()
        var subtoken = parser.nextToken()
        while (subtoken != JsonToken.END_OBJECT) {
          val key = parser.getCurrentName
          if (key == "@")
            _at = readString(parser, parser.nextToken(), dot + "." + key, at)
          else if (validSymbolName(key))
            items = (key, readCell(parser, parser.nextToken(), dot + "." + key, _at, avroTypeBuilder)) :: items
          else
            throw new PFASyntaxException("\"%s\" is not a valid symbol name".format(key), dot, at)
          subtoken = parser.nextToken()
        }
        items.toMap
      }
      case x => throw new PFASyntaxException("expected map of cells, found %s".format(tokenMessage.getOrElse(x, x.toString)), dot, at)
    }

    private def readCell(parser: JsonParser, token: JsonToken, dot: String, at: String, avroTypeBuilder: AvroTypeBuilder): Cell = token match {
      case JsonToken.START_OBJECT => {
        var _at = jsonAt(parser)

        val keys = mutable.Set[String]()
        var _avroType: AvroPlaceholder = null
        var _init: String = null
        var _shared: Boolean = false

        var subtoken = parser.nextToken()
        while (subtoken != JsonToken.END_OBJECT) {
          val key = parser.getCurrentName
          if (key == "@")
            _at = readString(parser, parser.nextToken(), dot + "." + key, at)
          else {
            keys.add(key)
            key match {
              case "type" => _avroType = readAvroPlaceholder(parser, parser.nextToken(), dot + "." + key, _at, avroTypeBuilder)
              case "init" => _init = readJsonToString(parser, parser.nextToken(), dot + "." + key, _at)
              case "shared" => _shared = readBoolean(parser, parser.nextToken(), dot + "." + key, _at)
              case x => throw new PFASyntaxException("unexpected cell property: %s".format(x), dot, _at)
            }
          }
          subtoken = parser.nextToken()
        }
        
        if (keys != Set("type", "init")  &&  keys != Set("type", "init", "shared"))
          throw new PFASyntaxException("wrong set of fields for cell: %s".format(keys.mkString(", ")), dot, _at)
        else
          Cell(_avroType, _init, _shared, Some(pos(dot, _at)))
      }
      case x => throw new PFASyntaxException("expected cell, found %s".format(tokenMessage.getOrElse(x, x.toString)), dot, at)
    }

    private def readPools(parser: JsonParser, token: JsonToken, dot: String, at: String, avroTypeBuilder: AvroTypeBuilder): Map[String, Pool] = token match {
      case JsonToken.START_OBJECT => {
        var _at = jsonAt(parser)

        var items = List[(String, Pool)]()
        var subtoken = parser.nextToken()
        while (subtoken != JsonToken.END_OBJECT) {
          val key = parser.getCurrentName
          if (key == "@")
            _at = readString(parser, parser.nextToken(), dot + "." + key, at)
          else if (validSymbolName(key))
            items = (key, readPool(parser, parser.nextToken(), dot + "." + key, _at, avroTypeBuilder)) :: items
          else
            throw new PFASyntaxException("\"%s\" is not a valid symbol name".format(key), dot, at)
          subtoken = parser.nextToken()
        }
        items.toMap
      }
      case x => throw new PFASyntaxException("expected map of pools, found %s".format(tokenMessage.getOrElse(x, x.toString)), dot, at)
    }

    private def readPool(parser: JsonParser, token: JsonToken, dot: String, at: String, avroTypeBuilder: AvroTypeBuilder): Pool = token match {
      case JsonToken.START_OBJECT => {
        var _at = jsonAt(parser)

        val keys = mutable.Set[String]()
        var _avroType: AvroPlaceholder = null
        var _init: Map[String, String] = Map[String, String]()
        var _shared: Boolean = false

        var subtoken = parser.nextToken()
        while (subtoken != JsonToken.END_OBJECT) {
          val key = parser.getCurrentName
          if (key == "@")
            _at = readString(parser, parser.nextToken(), dot + "." + key, at)
          else {
            keys.add(key)
            key match {
              case "type" => _avroType = readAvroPlaceholder(parser, parser.nextToken(), dot + "." + key, _at, avroTypeBuilder)
              case "init" => _init = readJsonToStringMap(parser, parser.nextToken(), dot + "." + key, _at)
              case "shared" => _shared = readBoolean(parser, parser.nextToken(), dot + "." + key, _at)
              case x => throw new PFASyntaxException("unexpected pool property: %s".format(x), dot, _at)
            }
          }
          subtoken = parser.nextToken()
        }
        
        if (keys != Set("type")  &&  keys != Set("type", "init")  &&  keys != Set("type", "init", "shared"))
          throw new PFASyntaxException("wrong set of fields for pool: %s".format(keys.mkString(", ")), dot, _at)
        else
          Pool(_avroType, _init, _shared, Some(pos(dot, _at)))
      }
      case x => throw new PFASyntaxException("expected pool, found %s".format(tokenMessage.getOrElse(x, x.toString)), dot, at)
    }
  }
}
