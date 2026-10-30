-- SPDX-License-Identifier: MIT
-- Copyright (c) 2026 Marek Cingel

-- Characterization of the unmodified pin, NOT a differential runner.
assert(_VERSION == "Lua 5.2", "This audit requires stock Lua 5.2 (bit32, table.unpack)")
local source = assert(arg[1], "Expected verified upstream source directory")
package.path = source .. "/?.lua;" .. source .. "/?/init.lua"
package.cpath = ""
local asn1 = require("asn1")
local count = 0

local function bytes(hex)
   return (hex:gsub("%s", ""):gsub("..", function(oct)
      return string.char(tonumber(oct, 16))
   end))
end

local function check(id, body)
   local ok, err = pcall(body)
   assert(ok, id .. ": " .. tostring(err))
   count = count + 1
   print("ok " .. count .. " - " .. id)
end

local function rejects(fn, ...)
   assert(not pcall(fn, ...), "Expected rejection")
end

local function roundtrip(id, syntax, value, hex)
   check(id, function()
      local wire = bytes(hex)
      assert(syntax.encode(value) == wire, "Unexpected wire bytes")
      assert(syntax.decode(wire) == value, "Unexpected decoded value")
   end)
end

roundtrip("octets-empty", asn1.octet_string, "", "04 00")
roundtrip("octets-binary", asn1.octet_string, bytes("00 ff 41"), "04 03 00 ff 41")
roundtrip("boolean-false", asn1.boolean, false, "01 01 00")
roundtrip("boolean-true", asn1.boolean, true, "01 01 ff")
roundtrip("integer-positive", asn1.integer, 128, "02 02 00 80")
roundtrip("integer-lower-bound", asn1.integer, 1, "02 01 01")
roundtrip("integer-upper-bound", asn1.integer, 2147483647, "02 04 7f ff ff ff")
roundtrip("bit-string", asn1.bit_string, "101", "03 02 05 a0")
roundtrip("bit-string-empty", asn1.bit_string, "", "03 01 00")
roundtrip("ia5-string", asn1.ia5string, "ABC", "16 03 41 42 43")
roundtrip("implicit-context-30", asn1.octet_string{tag=30}, "A", "9e 01 41")
roundtrip("explicit-context", asn1.explicit(0, asn1.octet_string), "A", "a0 03 04 01 41")

check("short-length-127", function()
   local value = string.rep("A", 127)
   local wire = bytes("04 7f") .. value
   assert(asn1.octet_string.encode(value) == wire)
   assert(asn1.octet_string.decode(wire) == value)
end)

check("nested-sequence", function()
   local syntax = asn1.sequence{
      {"name", asn1.octet_string},
      {"nested", asn1.sequence_of(asn1.integer)}
   }
   local wire = bytes("30 0b 04 01 41 30 06 02 01 01 02 01 02")
   local value = syntax.decode(wire)
   assert(value.name == "A" and value.nested[1] == 1 and value.nested[2] == 2)
   assert(syntax.encode(value) == wire)
end)

check("empty-sequence-of", function()
   local syntax = asn1.sequence_of(asn1.octet_string)
   assert(#syntax.decode(bytes("30 00")) == 0)
   assert(syntax.encode({}) == bytes("30 00"))
end)

for _, fixture in ipairs{
   {"empty-input", ""}, {"truncated-tag-only", "04"},
   {"truncated-value", "04 02 41"}, {"truncated-long-header", "04 82 01"},
   {"trailing-element", "04 00 04 00"},
   {"high-tag", "9f 1f 01 41"}, {"indefinite-length", "04 80 00 00"},
   {"constructed-octets", "24 03 04 01 41"}
} do
   check(fixture[1], function() rejects(asn1.octet_string.decode, bytes(fixture[2])) end)
end

check("truncated-child", function()
   rejects(asn1.sequence_of(asn1.octet_string).decode, bytes("30 03 04 02 41"))
end)
check("indefinite-constructed", function()
   rejects(asn1.sequence_of(asn1.octet_string).decode, bytes("30 80 04 00 00 00"))
end)
check("negative-integer", function()
   rejects(asn1.integer.decode, bytes("02 01 ff"))
   rejects(asn1.integer.encode, -1)
end)
check("high-tag-encode", function()
   rejects(asn1.octet_string{tag=31}.encode, "A")
end)
check("application-private-classes", function()
   rejects(asn1.octet_string{tag=4, class="application"}.encode, "A")
   rejects(asn1.octet_string{tag=4, class="private"}.encode, "A")
end)

-- These characterize upstream limitations; they are not assertions of BER validity.
check("known-difference-long-length-128", function()
   local value = string.rep("A", 128)
   local wire = bytes("04 81 80") .. value
   rejects(asn1.octet_string.decode, wire)
   assert(asn1.octet_string.encode(value) == bytes("04 81 80") .. value)
end)
check("known-difference-long-length-256", function()
   local value = string.rep("A", 256)
   rejects(asn1.octet_string.decode, bytes("04 82 01 00") .. value)
   assert(asn1.octet_string.encode(value) == bytes("04 81 00") .. value)
end)
check("known-difference-long-length-255", function()
   local value = string.rep("A", 255)
   local wire = bytes("04 81 ff") .. value
   -- Some lengths happen to work; that does not make the long-form path reliable.
   assert(asn1.octet_string.decode(wire) == value)
   assert(asn1.octet_string.encode(value) == wire)
end)
check("known-difference-integer-zero", function()
   assert(asn1.integer.decode(bytes("02 01 00")) == 0)
   rejects(asn1.integer.encode, 0)
end)
check("ambiguous-nonminimal-length", function()
   -- Reversed shift operands make 0x81 00 decode as length eight.
   assert(asn1.octet_string.decode(bytes("04 81 00") .. "12345678") == "12345678")
end)
check("semantic-boolean-validation", function()
   assert(asn1.boolean.decode(bytes("01 00")) == true)
   assert(asn1.boolean.decode(bytes("01 02 00 ff")) == false)
end)
check("choice-false-limitation", function()
   local syntax = asn1.choice{{"flag", asn1.boolean}}
   rejects(syntax.decode, bytes("01 01 00"))
   rejects(syntax.encode, {flag=false})
end)

print(string.format("%s: %d capability checks passed", _VERSION, count))
