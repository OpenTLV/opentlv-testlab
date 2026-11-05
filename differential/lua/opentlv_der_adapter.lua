-- SPDX-License-Identifier: MIT
-- Copyright (c) 2026 Marek Cingel

-- Decodes and encodes TestLabReference-1 typed values with OpenTLV Lua's DER support only:
-- the DER Format and strict tree traversal for framing, the asn1.* codecs for primitive
-- contents and the DER Tree Writer for output. OpenTLV Lua binds no DER schema layer, so
-- matching tags to components is this adapter's own work. Every rejection names its
-- source, so a rejection made here is never mistaken for an OpenTLV verdict.
local opentlv = require("opentlv")

local DER = opentlv.formats.der
local CODECS = opentlv.codecs.asn1
local MAX_DEPTH = 32 -- The library's default DER traversal depth.
-- Tree Writer output never grows past its capacity (1024 by default); fixtures hold at most 4096 bytes.
local CAPACITY = 8192
-- Malformed or noncanonical input; LIMIT, allocation and API errors remain run failures.
local REJECTED = {
   [opentlv.errors.TRUNCATED] = true,
   [opentlv.errors.INVALID_LENGTH] = true,
   [opentlv.errors.INVALID_TAG] = true,
   [opentlv.errors.INVALID_TAG_SIZE] = true,
   [opentlv.errors.INVALID_VALUE] = true,
}
local LEAVES = {
   boolean = CODECS.boolean, integer = CODECS.integer, bit_string = CODECS.bit_string,
   octet_string = CODECS.octet_string, ia5string = CODECS.ia5_string, null = CODECS.null,
   object_identifier = CODECS.oid,
}
local Rejection = {}
local unpack = table.unpack or unpack

local function hex(bytes)
   return (bytes:gsub(".", function(char) return string.format("%02x", char:byte()) end))
end

local function unhex(text)
   return (text:gsub("..", function(octet) return string.char(tonumber(octet, 16)) end))
end

local function reject(source, detail, code)
   error(setmetatable({source = source, detail = detail, code = code}, Rejection), 0)
end

local function is_library_rejection(failure)
   return type(failure) == "table" and getmetatable(failure) ~= Rejection and REJECTED[failure.code]
end

-- Calls OpenTLV; a malformed-input error becomes a rejection by OpenTLV, anything else propagates.
local function library(operation, ...)
   local results = {pcall(operation, ...)}
   if results[1] then return unpack(results, 2) end
   local failure = results[2]
   if is_library_rejection(failure) then reject("opentlv", tostring(failure), failure.code) end
   if getmetatable(failure) == Rejection then error(failure, 0) end
   error(tostring(failure), 0)
end

-- Lua 5.2 numbers are exact through 2^53; the codecs return larger values as decimal strings.
local function decimal(number)
   return type(number) == "string" and number or string.format("%.0f", number)
end

local function matches(schema, element)
   if schema.kind ~= "choice" then return hex(element.tag) == schema.identifier end
   for _, alternative in ipairs(schema.alternatives) do
      if matches(alternative.type, element) then return true end
   end
   return false
end

local function children(element)
   local list, reader = {}, opentlv.reader(element.value, DER)
   while true do
      local child = library(reader.next, reader)
      if not child then return list end
      list[#list + 1] = child
   end
end

local decode_value

local function decode_leaf(schema, element)
   local decoded = library(LEAVES[schema.kind].decode, LEAVES[schema.kind], element.value)
   local kind = schema.kind
   if kind == "boolean" then return {kind = kind, value = decoded} end
   if kind == "integer" then return {kind = kind, value = decimal(decoded)} end
   if kind == "bit_string" then return {kind = kind, unused_bits = decoded.unused_bits, value = hex(decoded.data)} end
   if kind == "null" then return {kind = kind} end
   if kind == "object_identifier" then
      local arcs = {}
      for i, arc in ipairs(decoded) do arcs[i] = decimal(arc) end
      return {kind = kind, value = table.concat(arcs, ".")}
   end
   return {kind = kind, value = hex(decoded)}
end

-- Components in definition order, as asn1c reports them; an absent DEFAULT takes its default.
local function decode_fields(schema, found, depth)
   local fields = {}
   for _, field in ipairs(schema.fields) do
      local element = found[field.name]
      if element then
         fields[#fields + 1] = {name = field.name, value = decode_value(field.type, element, depth + 1)}
      elseif field.default then
         fields[#fields + 1] = {name = field.name, value = field.default}
      elseif not field.optional then
         reject("adapter", "missing component " .. field.name)
      end
   end
   return fields
end

local function decode_sequence(schema, element, depth)
   local list, found, index = children(element), {}, 1
   for _, field in ipairs(schema.fields) do
      if list[index] and matches(field.type, list[index]) then
         found[field.name] = list[index]
         index = index + 1
      end
   end
   if list[index] then reject("adapter", "unexpected component with tag " .. hex(list[index].tag)) end
   return {kind = "sequence", fields = decode_fields(schema, found, depth)}
end

-- Component order is accepted as encoded: canonical SET order is a schema rule OpenTLV Lua lacks.
local function decode_set(schema, element, depth)
   local found = {}
   for _, child in ipairs(children(element)) do
      local field
      for _, candidate in ipairs(schema.fields) do
         if matches(candidate.type, child) then field = candidate end
      end
      if not field then reject("adapter", "unexpected component with tag " .. hex(child.tag)) end
      if found[field.name] then reject("adapter", "repeated component " .. field.name) end
      found[field.name] = child
   end
   return {kind = "set", fields = decode_fields(schema, found, depth)}
end

function decode_value(schema, element, depth)
   if depth > MAX_DEPTH then error("Value nests deeper than the adapter limit", 0) end
   if schema.kind == "choice" then
      for _, alternative in ipairs(schema.alternatives) do
         if matches(alternative.type, element) then
            return {kind = "choice", alternative = alternative.name,
                    value = decode_value(alternative.type, element, depth + 1)}
         end
      end
      reject("adapter", "no alternative has tag " .. hex(element.tag))
   end
   if hex(element.tag) ~= schema.identifier then
      reject("adapter", "expected tag " .. schema.identifier .. ", found " .. hex(element.tag))
   end
   if LEAVES[schema.kind] then return decode_leaf(schema, element) end
   if schema.kind == "explicit" then
      local inner = children(element)
      if #inner ~= 1 then reject("adapter", "an explicit tag wraps exactly one element") end
      return decode_value(schema.inner, inner[1], depth + 1)
   end
   if schema.kind == "sequence" then return decode_sequence(schema, element, depth) end
   if schema.kind == "set" then return decode_set(schema, element, depth) end
   local items = {}
   for i, child in ipairs(children(element)) do items[i] = decode_value(schema.item, child, depth + 1) end
   return {kind = schema.kind, items = items}
end

local function leaf_argument(schema, value)
   local kind = schema.kind
   if kind == "boolean" or kind == "integer" then return value.value end
   if kind == "bit_string" then return {unused_bits = value.unused_bits, data = unhex(value.value)} end
   if kind == "null" then return nil end
   if kind == "object_identifier" then
      local arcs = {}
      for arc in value.value:gmatch("[^.]+") do arcs[#arcs + 1] = arc end
      return arcs
   end
   return unhex(value.value)
end

local function field_value(value, name)
   for _, field in ipairs(value.fields) do
      if field.name == name then return field.value end
   end
end

-- Writes what the value holds, in its order: OpenTLV Lua neither sorts SET OF items nor
-- omits DEFAULT values, so such a value is encoded as given.
local function encode_value(writer, schema, value)
   if schema.kind == "choice" then
      for _, alternative in ipairs(schema.alternatives) do
         if alternative.name == value.alternative then return encode_value(writer, alternative.type, value.value) end
      end
      error("Unknown alternative " .. tostring(value.alternative), 0)
   end
   local tag = unhex(schema.identifier)
   if LEAVES[schema.kind] then
      local codec = LEAVES[schema.kind]
      return library(writer.write, writer, tag, library(codec.encode, codec, leaf_argument(schema, value)))
   end
   library(writer.begin, writer, tag)
   if schema.kind == "explicit" then
      encode_value(writer, schema.inner, value)
   elseif schema.kind == "sequence" or schema.kind == "set" then
      for _, field in ipairs(schema.fields) do
         local member = field_value(value, field.name)
         if member then encode_value(writer, field.type, member) end
      end
   else
      for _, item in ipairs(value.items) do encode_value(writer, schema.item, item) end
   end
   library(writer.end_element, writer)
end

-- An argument the binding cannot represent, such as an INTEGER beyond int64, is unsupported.
local function encode(schema, value)
   local ok, result = pcall(function()
      local writer = opentlv.tree_writer(DER, {capacity = CAPACITY})
      encode_value(writer, schema, value)
      return library(writer.finish, writer)
   end)
   if ok then return {status = "encoded", wire = hex(result)} end
   if getmetatable(result) == Rejection then return {status = "failed", detail = result.detail} end
   if type(result) == "string" and result:find("out of range", 1, true) then
      return {status = "unsupported", detail = result}
   end
   error(result, 0)
end

-- Only the root can be truncated: a child that overruns its parent is invalid contents.
local function classify(failure, framing_complete)
   if not framing_complete and failure.code == opentlv.errors.TRUNCATED then return "truncated" end
   return "invalid"
end

local function decode(schema, wire)
   if #wire == 0 then return {status = "rejected", error = "empty", source = "opentlv"} end
   local framing_complete = false
   local ok, result = pcall(function()
      -- read_source() stops after one element; the complete-root policy is applied here.
      local element, source = library(opentlv.read_source, wire, DER)
      local consumed = #source:bytes()
      if consumed ~= #wire then
         return {status = "rejected", error = "trailing", source = "opentlv", consumed = consumed}
      end
      framing_complete = true
      library(opentlv.visit_tree, wire, DER, nil, {max_depth = MAX_DEPTH})
      return {status = "accepted", consumed = consumed, value = decode_value(schema, element, 0)}
   end)
   if ok then return result end
   if getmetatable(result) ~= Rejection then error(result, 0) end
   return {status = "rejected", error = classify(result, framing_complete), source = result.source,
           detail = result.detail}
end

local adapter = {}

function adapter.identity()
   return {adapter = "opentlv", version = opentlv.version(),
           module = package.searchpath("opentlv._core", package.cpath)}
end

function adapter.handle(request)
   if request.operation == "encode" then return {encode = encode(request.schema, request.value)} end
   local result = decode(request.schema, request.wire)
   if result.status == "accepted" then result.encode = encode(request.schema, result.value) end
   return result
end

return adapter
