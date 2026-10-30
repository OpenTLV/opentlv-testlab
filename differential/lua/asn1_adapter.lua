-- SPDX-License-Identifier: MIT
-- Copyright (c) 2026 Marek Cingel

-- lua-asn1 returns typed values, not TLV fields. Its tree is therefore projected
-- from the typed result through the fixture schema: never re-encoded by the library
-- and without length bytes, because this API cannot observe them.
local asn1 = require("asn1")

local UNIVERSAL = {boolean = 0x01, integer = 0x02, bit_string = 0x03,
                   octet_string = 0x04, ia5string = 0x16}
local SEQUENCE = 0x10
local CONSTRUCTED = 0x20
local CONTEXT = 0x80
local EXACT_NUMBER_LIMIT = 2 ^ 53

local function unsupported(reason) error({unsupported = reason}, 0) end

local function hex(bytes)
   return (bytes:gsub(".", function(char) return string.format("%02x", char:byte()) end))
end

local function identity(value) return value end

local PAYLOAD = {
   boolean = function(value) return value and "\255" or "\0" end,
   integer = function(value)
      if value >= EXACT_NUMBER_LIMIT then unsupported("INTEGER exceeds exact Lua numbers") end
      local octets = ""
      repeat
         octets = string.char(value % 256) .. octets
         value = math.floor(value / 256)
      until value == 0
      return octets:byte(1) >= 0x80 and "\0" .. octets or octets
   end,
   bit_string = function(value)
      local unused = (8 - #value % 8) % 8
      local bits = value .. string.rep("0", unused)
      local octets = string.char(unused)
      for i = 1, #bits, 8 do
         octets = octets .. string.char(tonumber(bits:sub(i, i + 7), 2))
      end
      return octets
   end,
   octet_string = identity,
   ia5string = identity,
}

local function build(schema)
   if schema.type == "explicit" then return asn1.explicit(schema.tag, build(schema.inner)) end
   local syntax
   if UNIVERSAL[schema.type] then
      syntax = asn1[schema.type]
   elseif schema.type == "sequence" then
      local components = {}
      for i, field in ipairs(schema.fields) do components[i] = {field.name, build(field.schema)} end
      syntax = asn1.sequence(components)
   elseif schema.type == "sequence_of" then
      syntax = asn1.sequence_of(build(schema.item))
   else
      unsupported("no lua-asn1 type for " .. tostring(schema.type))
   end
   if schema.class and schema.class ~= "context" then
      unsupported("no lua-asn1 tag class for " .. tostring(schema.class))
   end
   return schema.tag and syntax{tag = schema.tag} or syntax
end

local function identifier(schema, universal, flags)
   return string.format("%02x", (schema.tag and CONTEXT + schema.tag or universal) + flags)
end

local function encoded_size(length)
   local size = 2
   if length >= 0x80 then
      repeat
         size = size + 1
         length = math.floor(length / 256)
      until length == 0
   end
   return size
end

local function constructed(id, children)
   local length = 0
   for _, child in ipairs(children) do length = length + encoded_size(child.length) + child.length end
   return {identifier = id, length = length, children = children}
end

local function project(schema, value)
   if schema.type == "explicit" then
      return constructed(string.format("%02x", CONTEXT + CONSTRUCTED + schema.tag),
                         {project(schema.inner, value)})
   end
   if UNIVERSAL[schema.type] then
      local payload = PAYLOAD[schema.type](value)
      return {identifier = identifier(schema, UNIVERSAL[schema.type], 0),
              length = #payload, value = hex(payload)}
   end
   local children = {}
   if schema.type == "sequence" then
      for i, field in ipairs(schema.fields) do children[i] = project(field.schema, value[field.name]) end
   else
      for i, item in ipairs(value) do children[i] = project(schema.item, item) end
   end
   return constructed(identifier(schema, SEQUENCE, CONSTRUCTED), children)
end

local function decode(request)
   local syntax = build(request.schema)
   local ok, value = pcall(syntax.decode, request.wire)
   if not ok then
      local detail = tostring(value)
      if detail:find("stack overflow", 1, true) or detail:find("not enough memory", 1, true) then
         error(detail, 0)
      end
      return {status = "rejected", detail = (detail:gsub("^.-/asn1/init%.lua:", "asn1/init.lua:"))}
   end
   -- A successful typed decode has already required the whole input to be one element.
   return {status = "accepted", consumed = #request.wire, projected = true, typed = value,
           tree = project(request.schema, value)}
end

local adapter = {}

function adapter.identity()
   return {adapter = "lua-asn1", module = package.searchpath("asn1", package.path)}
end

function adapter.decode(request)
   local ok, result = pcall(decode, request)
   if ok then return result end
   if type(result) == "table" then return {status = "unsupported", detail = result.unsupported} end
   error(result, 0)
end

return adapter
