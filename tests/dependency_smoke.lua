-- SPDX-License-Identifier: MIT
-- Copyright (c) 2026 Marek Cingel

assert(_VERSION == "Lua 5.2")
local version, native = assert(arg[1]), assert(arg[2])
assert(package.searchpath("opentlv._core", package.cpath) == native,
       "OpenTLV native module must come from the fresh installation")
local opentlv = require("opentlv")
assert(opentlv == require("opentlv._core"))
assert(opentlv.version() == version and opentlv._VERSION == version)
local wire = string.char(4, 3, 0, 255, 65)
local element, consumed = opentlv.read(wire, opentlv.formats.ber)
assert(consumed == #wire and element.tag == string.char(4))
assert(element.value == string.char(0, 255, 65))
assert(opentlv.formats.ber:encode(element.tag, element.value) == wire)
print("Fresh OpenTLV " .. version .. " package loaded: " .. native)
