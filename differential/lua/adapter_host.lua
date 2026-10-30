-- SPDX-License-Identifier: MIT
-- Copyright (c) 2026 Marek Cingel

-- Runs ONE adapter over the requests on stdin and writes JSON lines to stdout:
-- the adapter identity, then one flushed result per request. Library failures
-- that are not decode results propagate, so they exit nonzero as run failures.
assert(_VERSION == "Lua 5.2", "The initial differential runner requires Lua 5.2")
local adapter = dofile(assert(arg[1], "Expected adapter path"))
-- Requests are data: text chunks only, with no access to any global.
local requests = assert(load(io.read("*a"), "=requests", "t", {}))()

local function json_string(text)
   return '"' .. text:gsub('[%c"\\\128-\255]', function(char)
      return string.format("\\u%04x", char:byte())
   end) .. '"'
end

local function json(value)
   local kind = type(value)
   if kind == "string" then return json_string(value) end
   if kind == "boolean" then return tostring(value) end
   if kind == "number" then
      return value == math.floor(value) and string.format("%.0f", value)
         or string.format("%.17g", value)
   end
   assert(kind == "table", "Unsupported result type: " .. kind)
   local parts = {}
   if next(value) == nil or #value > 0 then
      for i, item in ipairs(value) do parts[i] = json(item) end
      return "[" .. table.concat(parts, ",") .. "]"
   end
   local keys = {}
   for key in pairs(value) do keys[#keys + 1] = key end
   table.sort(keys)
   for i, key in ipairs(keys) do parts[i] = json_string(key) .. ":" .. json(value[key]) end
   return "{" .. table.concat(parts, ",") .. "}"
end

local function emit(record)
   io.write(json(record), "\n")
   io.flush()
end

local identity = adapter.identity()
identity.runtime = _VERSION
emit(identity)

for _, request in ipairs(requests) do
   request.wire = request.wire:gsub("..", function(octet)
      return string.char(tonumber(octet, 16))
   end)
   local result = adapter.decode(request)
   result.id = request.id
   emit(result)
end
