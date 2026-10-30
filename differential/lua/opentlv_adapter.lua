-- SPDX-License-Identifier: MIT
-- Copyright (c) 2026 Marek Cingel

-- Observes raw BER framing only: it never receives the fixture schema, and
-- ASN.1 primitive semantics are not validated by this OpenTLV API.
local opentlv = require("opentlv")

local BER = opentlv.formats.ber
local MAX_DEPTH = 64 -- Matches the library's default tree depth.
-- Malformed input only; LIMIT, allocation and API errors remain run failures.
local REJECTED = {
   [opentlv.errors.TRUNCATED] = true,
   [opentlv.errors.INVALID_LENGTH] = true,
   [opentlv.errors.INVALID_TAG] = true,
}

local function hex(bytes)
   return (bytes:gsub(".", function(char) return string.format("%02x", char:byte()) end))
end

-- Elements do not carry their original length bytes; a Source preserves them.
local function length_bytes(source)
   local field = source:layout().length
   return source:bytes():sub(field.offset + 1, field.offset + field.size)
end

local function normalize(element, source, depth)
   local node = {identifier = hex(element.tag), length = element.length,
                 length_bytes = hex(length_bytes(source))}
   if element.tag:byte(1) % 0x40 < 0x20 then
      node.value = hex(element.value)
      return node
   end
   if depth >= MAX_DEPTH then error("Nesting exceeds the adapter limit", 0) end
   node.children = {}
   local reader = opentlv.reader(element.value, BER)
   while true do
      local child, child_source = reader:next_source()
      if not child then return node end
      node.children[#node.children + 1] = normalize(child, child_source, depth + 1)
   end
end

-- Reader accepts streams and read_source() stops after one element, so the complete-root
-- policy is applied here, before any byte after the first root is interpreted.
local function parse(wire)
   local element, source = opentlv.read_source(wire, BER)
   if not element then return {status = "rejected", detail = "no root element"} end
   local consumed = #source:bytes()
   if consumed ~= #wire then
      return {status = "rejected", consumed = consumed, detail = "bytes after the first root"}
   end
   return {status = "accepted", consumed = consumed, tree = normalize(element, source, 1)}
end

local adapter = {}

function adapter.identity()
   return {adapter = "opentlv", version = opentlv.version(),
           module = package.searchpath("opentlv._core", package.cpath)}
end

function adapter.decode(request)
   local ok, result = pcall(parse, request.wire)
   if ok then return result end
   if type(result) == "table" and REJECTED[result.code] then
      return {status = "rejected", detail = tostring(result)}
   end
   error(tostring(result), 0)
end

return adapter
