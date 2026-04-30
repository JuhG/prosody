local jid       = require "util.jid";
local json      = require "util.json";
local st        = require "util.stanza";
local encodings = require "util.encodings";
local b64       = encodings.base64;

local ok_pkey,   pkey           = pcall(require, "openssl.pkey");
local ok_digest, openssl_digest = pcall(require, "openssl.digest");
local ok_http,   http_request   = pcall(require, "http.request");

if not (ok_pkey and ok_digest and ok_http) then
	module:log("error", "mod_voip_push requires luaossl and lua-http — install via luarocks");
	return;
end

local APNS_KEY_PEM   = os.getenv("APNS_KEY");
local APNS_KEY_ID    = os.getenv("APNS_KEY_ID");
local APNS_TEAM_ID   = os.getenv("APNS_TEAM_ID");
local APNS_BUNDLE_ID = os.getenv("APNS_BUNDLE_ID");

if not (APNS_KEY_PEM and APNS_KEY_ID and APNS_TEAM_ID and APNS_BUNDLE_ID) then
	module:log("error", "Missing APNS_KEY / APNS_KEY_ID / APNS_TEAM_ID / APNS_BUNDLE_ID env vars");
	return;
end

local apns_key = assert(pkey.new(APNS_KEY_PEM));
local token_store = module:open_store("voip_tokens");

local function base64url(s)
	return (b64.encode(s):gsub("+", "-"):gsub("/", "_"):gsub("=+$", ""));
end

-- Convert DER ECDSA signature to raw 64-byte r||s required by JWT
local function der_to_raw(der)
	local pos = 2;
	local len_byte = der:byte(pos);
	if len_byte >= 128 then
		pos = pos + (len_byte - 128);
	end
	pos = pos + 1;

	local function read_int(p)
		p = p + 1;
		local n = der:byte(p);
		p = p + 1;
		local v = der:sub(p, p + n - 1);
		return v, p + n;
	end

	local r, s;
	r, pos = read_int(pos);
	s      = read_int(pos);

	while #r > 32 do r = r:sub(2) end
	while #s > 32 do s = s:sub(2) end
	while #r < 32 do r = "\0" .. r end
	while #s < 32 do s = "\0" .. s end
	return r .. s;
end

-- APNs JWTs are valid for 1 hour; cache to avoid signing on every push
local jwt_cache, jwt_cached_at;
local JWT_TTL = 55 * 60;

local function make_jwt()
	local now = os.time();
	if jwt_cache and (now - jwt_cached_at) < JWT_TTL then
		return jwt_cache;
	end
	local hdr = base64url(json.encode({ alg = "ES256", kid = APNS_KEY_ID }));
	local pld = base64url(json.encode({ iss = APNS_TEAM_ID, iat = now }));
	local msg = hdr .. "." .. pld;
	local d   = openssl_digest.new("sha256");
	d:update(msg);
	jwt_cache    = msg .. "." .. base64url(der_to_raw(apns_key:sign(d)));
	jwt_cached_at = now;
	return jwt_cache;
end

local function send_push(device_token, call_id, caller_jid, caller_name)
	local body = json.encode({
		aps      = {},
		callType = "xmpp",
		callId   = call_id,
		peerJid  = caller_jid,
		peerName = caller_name,
	});

	local req = http_request.new_from_uri(
		"https://api.push.apple.com/3/device/" .. device_token
	);
	req.headers:upsert(":method",         "POST");
	req.headers:upsert("authorization",   "bearer " .. make_jwt());
	req.headers:upsert("apns-topic",      APNS_BUNDLE_ID .. ".voip");
	req.headers:upsert("apns-push-type",  "voip");
	req.headers:upsert("apns-expiration", "0");
	req.headers:upsert("apns-priority",   "10");
	req.headers:upsert("content-type",    "application/json");
	req:set_body(body);

	local ok, result = pcall(function()
		local headers, stream = assert(req:go(10));
		local status = headers:get(":status");
		local body = stream:get_body_as_string() or "";
		return { status = status, body = body };
	end);

	if not ok then
		module:log("warn", "APNs push failed: %s", tostring(result));
	elseif result.status ~= "200" then
		module:log("warn", "APNs returned %s for token %s: %s", result.status, device_token, result.body);
	else
		module:log("info", "APNs push sent to %s", device_token);
	end
end

module:hook("iq-set/self/urn:messagely:v4:notifications:register-voip-token:query", function(event)
	local origin, stanza = event.origin, event.stanza;
	local token = stanza:find("query/token#");
	if not token then
		origin.send(st.error_reply(stanza, "modify", "bad-request", "Missing token"));
		return true;
	end
	token_store:set(origin.username, { token = token });
	module:log("info", "VoIP token registered for %s", origin.username);
	origin.send(st.reply(stanza));
	return true;
end);

module:hook("iq/full", function(event)
	local stanza = event.stanza;
	if stanza.attr.type ~= "set" then return; end

	local jingle = stanza:find("{urn:xmpp:jingle:1}jingle");
	if not jingle or jingle.attr.action ~= "session-initiate" then return; end

	local to_user = jid.split(stanza.attr.to);
	if hosts[module.host].sessions[to_user] then return; end

	local data = token_store:get(to_user);
	if not data then return; end

	send_push(
		data.token,
		jingle.attr.sid,
		stanza.attr.from,
		jid.split(stanza.attr.from)
	);
end, 1);
