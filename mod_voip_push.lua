local jid       = require "util.jid";
local json      = require "util.json";
local st        = require "util.stanza";
local encodings = require "util.encodings";
local b64       = encodings.base64;

local ok_pkey,   pkey           = pcall(require, "openssl.pkey");
local ok_digest, openssl_digest = pcall(require, "openssl.digest");

if not (ok_pkey and ok_digest) then
	module:log("error", "mod_voip_push requires luaossl — install via luarocks");
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
module:log("info", "mod_voip_push loaded, APNs team=%s key=%s bundle=%s", APNS_TEAM_ID, APNS_KEY_ID, APNS_BUNDLE_ID);

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

local function shell_escape(s)
	return "'" .. s:gsub("'", "'\\''") .. "'";
end

local function send_push(device_token, call_id, caller_jid, caller_name)
	local payload = json.encode({
		aps      = {},
		callType = "xmpp",
		callId   = call_id,
		peerJid  = caller_jid,
		peerName = caller_name,
	});

	local jwt = make_jwt();
	local url = "https://api.push.apple.com/3/device/" .. device_token;

	local cmd = string.format(
		"curl -s -w '\\n%%{http_code}' --http2 -X POST"
		.. " -H 'authorization: bearer %s'"
		.. " -H 'apns-topic: %s.voip'"
		.. " -H 'apns-push-type: voip'"
		.. " -H 'apns-expiration: 0'"
		.. " -H 'apns-priority: 10'"
		.. " -H 'content-type: application/json'"
		.. " -d %s %s 2>&1",
		jwt, APNS_BUNDLE_ID, shell_escape(payload), shell_escape(url)
	);

	local handle = io.popen(cmd);
	local output = handle:read("*a");
	handle:close();

	local response_body, status = output:match("^(.-)\n(%d+)%s*$");
	if not status then
		module:log("warn", "APNs push failed (curl): %s", output);
	elseif status ~= "200" then
		module:log("warn", "APNs returned %s for token %s: %s", status, device_token, response_body or "");
	else
		module:log("info", "APNs push sent to %s", device_token);
	end
end

local VOIP_NS = "urn:messagely:v4:notifications:register-voip-token";

module:hook("iq-set/self/" .. VOIP_NS .. ":query", function(event)
	local origin, stanza = event.origin, event.stanza;
	local token = stanza:find("{" .. VOIP_NS .. "}query/token#")
		or stanza:find("{" .. VOIP_NS .. "}query/{" .. VOIP_NS .. "}token#");
	if not token then
		module:log("warn", "Missing token in VoIP registration IQ: %s", tostring(stanza));
		origin.send(st.error_reply(stanza, "modify", "bad-request", "Missing token"));
		return true;
	end
	token_store:set(origin.username, { token = token });
	module:log("info", "VoIP token registered for %s", origin.username);
	origin.send(st.reply(stanza));
	return true;
end);

local function handle_jingle_initiate(event)
	local stanza = event.stanza;
	if stanza.attr.type ~= "set" then return; end

	local jingle = stanza:find("{urn:xmpp:jingle:1}jingle");
	if not jingle or jingle.attr.action ~= "session-initiate" then return; end

	local to_user = jid.split(stanza.attr.to);
	module:log("info", "Jingle session-initiate from %s to %s", stanza.attr.from, stanza.attr.to);

	local sessions = hosts[module.host].sessions[to_user];
	if sessions then
		module:log("info", "User %s is online, skipping push", to_user);
		return;
	end

	module:log("info", "User %s is offline, looking up VoIP token", to_user);
	local data = token_store:get(to_user);
	if not data then
		module:log("warn", "No VoIP token stored for %s", to_user);
		return;
	end

	module:log("info", "Sending VoIP push to %s (token: %s...)", to_user, data.token:sub(1, 8));
	send_push(
		data.token,
		jingle.attr.sid,
		stanza.attr.from,
		jid.split(stanza.attr.from)
	);
end

module:hook("iq/full", handle_jingle_initiate, 1);
module:hook("iq/bare", handle_jingle_initiate, 1);
