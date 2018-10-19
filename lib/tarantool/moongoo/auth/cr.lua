local pass_digest = require("tarantool.moongoo.utils").pass_digest

local b64 = function(str) return require('digest').base64_encode(str, {nowrap = true}) end
local unb64 = function(str) return require('digest').base64_decode(str) end

local tohex = function (str) return (str:gsub('.', function (c) return string.format('%02x', string.byte(c)) end)) end
local md5 = function(str) return tohex(require("crypto").digest.md5(str)) end

local cbson = require("cbson")


local function auth(db, username, password)
  local r, err = db:_cmd("getnonce", {})
  if not r then
      return nil, err
  end

  local digest = md5( r.nonce .. username .. pass_digest ( username , password ) )

  r, err = db:_cmd("authenticate", {
    user = username ;
    nonce = r.nonce ;
    key = digest ;
  })

  if not r then
    return nil, err
  end

  return 1
end

return auth