package com.muse.gadget.util

/**
 * Minimal JSON parser/stringifier for the small, known shapes this module
 * handles (pairing envelopes, NDJSON subscribe events, API bodies).
 * Dependency-free on purpose: the :protocol module must stay pure JVM.
 */
sealed interface JsonValue {
    data class Obj(val fields: LinkedHashMap<String, JsonValue>) : JsonValue
    data class Arr(val items: List<JsonValue>) : JsonValue
    data class Str(val value: String) : JsonValue
    data class Num(val raw: String) : JsonValue
    data object True : JsonValue
    data object False : JsonValue
    data object Null : JsonValue
}

class JsonParseException(message: String) : IllegalArgumentException(message)

object Json {
    fun parse(text: String): JsonValue {
        val p = Parser(text)
        val v = p.parseValue()
        p.skipWs()
        if (!p.atEnd()) throw JsonParseException("trailing characters after JSON value")
        return v
    }

    fun parseObj(text: String): JsonValue.Obj {
        val v = parse(text)
        if (v !is JsonValue.Obj) throw JsonParseException("expected JSON object")
        return v
    }

    fun stringify(v: JsonValue): String = buildString { appendValue(v) }

    /** Compact object builder, e.g. obj("a" to str("x"), "b" to num(1)). */
    fun obj(vararg pairs: Pair<String, JsonValue>): JsonValue.Obj =
        JsonValue.Obj(LinkedHashMap<String, JsonValue>().also { m ->
            for ((k, value) in pairs) m[k] = value
        })

    fun str(s: String): JsonValue.Str = JsonValue.Str(s)
    fun num(n: Number): JsonValue.Num = JsonValue.Num(n.toString())
    fun bool(b: Boolean): JsonValue = if (b) JsonValue.True else JsonValue.False

    private fun StringBuilder.appendValue(v: JsonValue) {
        when (v) {
            is JsonValue.Obj -> {
                append('{')
                v.fields.entries.forEachIndexed { i, (k, value) ->
                    if (i > 0) append(',')
                    appendString(k)
                    append(':')
                    appendValue(value)
                }
                append('}')
            }
            is JsonValue.Arr -> {
                append('[')
                v.items.forEachIndexed { i, item ->
                    if (i > 0) append(',')
                    appendValue(item)
                }
                append(']')
            }
            is JsonValue.Str -> appendString(v.value)
            is JsonValue.Num -> append(v.raw)
            JsonValue.True -> append("true")
            JsonValue.False -> append("false")
            JsonValue.Null -> append("null")
        }
    }

    private fun StringBuilder.appendString(s: String) {
        append('"')
        for (c in s) {
            when (c) {
                '"' -> append("\\\"")
                '\\' -> append("\\\\")
                '\b' -> append("\\b")
                '\u000C' -> append("\\f")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> if (c < ' ') append("\\u%04x".format(c.code)) else append(c)
            }
        }
        append('"')
    }

    private class Parser(val text: String) {
        var pos = 0

        fun atEnd(): Boolean = pos >= text.length

        fun skipWs() {
            while (pos < text.length && text[pos] in " \t\n\r") pos++
        }

        fun parseValue(): JsonValue {
            skipWs()
            if (atEnd()) throw JsonParseException("unexpected end of input")
            return when (val c = text[pos]) {
                '{' -> parseObject()
                '[' -> parseArray()
                '"' -> JsonValue.Str(parseString())
                't' -> expectLiteral("true", JsonValue.True)
                'f' -> expectLiteral("false", JsonValue.False)
                'n' -> expectLiteral("null", JsonValue.Null)
                '-', in '0'..'9' -> parseNumber()
                else -> throw JsonParseException("unexpected character '$c' at $pos")
            }
        }

        private fun parseObject(): JsonValue.Obj {
            pos++ // {
            val map = LinkedHashMap<String, JsonValue>()
            skipWs()
            if (pos < text.length && text[pos] == '}') {
                pos++
                return JsonValue.Obj(map)
            }
            while (true) {
                skipWs()
                if (atEnd() || text[pos] != '"') throw JsonParseException("expected string key at $pos")
                val key = parseString()
                skipWs()
                if (atEnd() || text[pos] != ':') throw JsonParseException("expected ':' at $pos")
                pos++
                map[key] = parseValue()
                skipWs()
                if (atEnd()) throw JsonParseException("unterminated object")
                when (text[pos]) {
                    ',' -> { pos++; continue }
                    '}' -> { pos++; return JsonValue.Obj(map) }
                    else -> throw JsonParseException("expected ',' or '}' at $pos")
                }
            }
        }

        private fun parseArray(): JsonValue.Arr {
            pos++ // [
            val list = ArrayList<JsonValue>()
            skipWs()
            if (pos < text.length && text[pos] == ']') {
                pos++
                return JsonValue.Arr(list)
            }
            while (true) {
                list.add(parseValue())
                skipWs()
                if (atEnd()) throw JsonParseException("unterminated array")
                when (text[pos]) {
                    ',' -> { pos++; continue }
                    ']' -> { pos++; return JsonValue.Arr(list) }
                    else -> throw JsonParseException("expected ',' or ']' at $pos")
                }
            }
        }

        private fun parseString(): String {
            pos++ // opening "
            val sb = StringBuilder()
            while (true) {
                if (pos >= text.length) throw JsonParseException("unterminated string")
                val c = text[pos++]
                when (c) {
                    '"' -> return sb.toString()
                    '\\' -> {
                        if (pos >= text.length) throw JsonParseException("unterminated escape")
                        when (val e = text[pos++]) {
                            '"', '\\', '/' -> sb.append(e)
                            'b' -> sb.append('\b')
                            'f' -> sb.append('\u000C')
                            'n' -> sb.append('\n')
                            'r' -> sb.append('\r')
                            't' -> sb.append('\t')
                            'u' -> {
                                if (pos + 4 > text.length) throw JsonParseException("bad \\u escape")
                                val hex = text.substring(pos, pos + 4)
                                val code = hex.toIntOrNull(16)
                                    ?: throw JsonParseException("bad \\u escape: $hex")
                                pos += 4
                                // surrogate pairs
                                if (code in 0xD800..0xDBFF && pos + 6 <= text.length &&
                                    text[pos] == '\\' && text[pos + 1] == 'u'
                                ) {
                                    val lo = text.substring(pos + 2, pos + 6).toIntOrNull(16)
                                    if (lo != null && lo in 0xDC00..0xDFFF) {
                                        pos += 6
                                        sb.append(
                                            Character.toString(
                                                0x10000 + ((code - 0xD800) shl 10) + (lo - 0xDC00),
                                            ),
                                        )
                                        continue
                                    }
                                }
                                sb.append(code.toChar())
                            }
                            else -> throw JsonParseException("bad escape '\\$e'")
                        }
                    }
                    else -> {
                        if (c < ' ') throw JsonParseException("unescaped control character")
                        sb.append(c)
                    }
                }
            }
        }

        private fun parseNumber(): JsonValue.Num {
            val start = pos
            if (pos < text.length && text[pos] == '-') pos++
            if (atEnd()) throw JsonParseException("bad number")
            if (text[pos] == '0') {
                pos++
            } else if (text[pos] in '1'..'9') {
                while (pos < text.length && text[pos] in '0'..'9') pos++
            } else {
                throw JsonParseException("bad number at $pos")
            }
            if (pos < text.length && text[pos] == '.') {
                pos++
                if (atEnd() || text[pos] !in '0'..'9') throw JsonParseException("bad number fraction")
                while (pos < text.length && text[pos] in '0'..'9') pos++
            }
            if (pos < text.length && (text[pos] == 'e' || text[pos] == 'E')) {
                pos++
                if (pos < text.length && (text[pos] == '+' || text[pos] == '-')) pos++
                if (atEnd() || text[pos] !in '0'..'9') throw JsonParseException("bad number exponent")
                while (pos < text.length && text[pos] in '0'..'9') pos++
            }
            return JsonValue.Num(text.substring(start, pos))
        }

        private fun expectLiteral(literal: String, value: JsonValue): JsonValue {
            if (!text.startsWith(literal, pos)) throw JsonParseException("bad literal at $pos")
            pos += literal.length
            return value
        }
    }
}

/** Convenience accessors. */
fun JsonValue.obj(): JsonValue.Obj = this as JsonValue.Obj
fun JsonValue.field(name: String): JsonValue? = (this as? JsonValue.Obj)?.fields?.get(name)
fun JsonValue.strField(name: String): String? = (field(name) as? JsonValue.Str)?.value
fun JsonValue.numField(name: String): JsonValue.Num? = field(name) as? JsonValue.Num
fun JsonValue.boolField(name: String): Boolean? = when (val v = field(name)) {
    JsonValue.True -> true
    JsonValue.False -> false
    else -> null
}
