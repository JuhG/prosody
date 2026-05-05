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

local function send_push(device_token, sandbox, call_id, caller_jid, caller_name)
	local payload = json.encode({
		aps      = {},
		callType = "xmpp",
		callId   = call_id,
		peerJid  = caller_jid,
		peerName = caller_name,
	});

	local jwt = make_jwt();
	local apns_host = sandbox and "api.sandbox.push.apple.com" or "api.push.apple.com";
	local url = "https://" .. apns_host .. "/3/device/" .. device_token;
	local token_prefix = device_token:sub(1, 8);

	-- -i includes response headers in stdout so we can extract apns-id;
	-- -w appends a marker line with the HTTP status. On connect failure curl
	-- still prints the marker with status=000. The body, when present, is the
	-- JSON error doc from APNs (e.g. {"reason":"BadDeviceToken"}).
	local cmd = string.format(
		"curl -s -i -w '\\n__STATUS__:%%{http_code}' --http2 -X POST"
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

	local status  = output:match("__STATUS__:(%d+)");
	local apns_id = output:match("[Aa]pns%-[Ii]d:%s*([^\r\n]+)");
	-- Body is between the blank line after headers and our __STATUS__ marker.
	local body    = output:match("\r?\n\r?\n(.-)\n__STATUS__:") or "";
	local reason  = body:match('"reason"%s*:%s*"([^"]+)"');

	if not status or status == "000" then
		module:log("warn", "APNs push failed: host=%s token=%s… status=%s output=%s",
			apns_host, token_prefix, status or "none", output);
	elseif status ~= "200" then
		module:log("warn", "APNs %s: host=%s token=%s… apns-id=%s reason=%s body=%s",
			status, apns_host, token_prefix, apns_id or "?", reason or "?", body);
	else
		module:log("info", "APNs push sent: host=%s token=%s… apns-id=%s",
			apns_host, token_prefix, apns_id or "?");
	end
end

local VOIP_NS = "urn:messagely:v4:notifications:register-voip-token";

module:hook("iq-set/self/" .. VOIP_NS .. ":query", function(event)
	local origin, stanza = event.origin, event.stanza;
	local query = stanza:find("{" .. VOIP_NS .. "}query");

	-- <remove/> child clears any stored token (sent on logout).
	if query and (query:get_child("remove") or query:get_child("remove", VOIP_NS)) then
		token_store:set(origin.username, nil);
		module:log("info", "VoIP token cleared for %s", origin.username);
		origin.send(st.reply(stanza));
		return true;
	end

	local token_el = query and (query:get_child("token") or query:get_child("token", VOIP_NS));
	local token = token_el and token_el:get_text();
	if not token or token == "" then
		module:log("warn", "Missing token in VoIP registration IQ: %s", tostring(stanza));
		origin.send(st.error_reply(stanza, "modify", "bad-request", "Missing token"));
		return true;
	end

	-- env="sandbox" → APNs sandbox host; anything else (or missing) → production.
	local env = token_el.attr.env;
	local sandbox = (env == "sandbox");
	token_store:set(origin.username, { token = token, sandbox = sandbox });
	module:log("info", "VoIP token registered for %s (env=%s)", origin.username, env or "production");
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

	module:log("info", "Sending VoIP push to %s (token: %s..., sandbox=%s)",
		to_user, data.token:sub(1, 8), tostring(data.sandbox or false));
	send_push(
		data.token,
		data.sandbox or false,
		jingle.attr.sid,
		stanza.attr.from,
		jid.split(stanza.attr.from)
	);
end

module:hook("iq/full", handle_jingle_initiate, 1);
module:hook("iq/bare", handle_jingle_initiate, 1);

-- An IQ to a bare JID with an unknown payload is normally answered by the
-- server with <service-unavailable/> (RFC 6121 §8.5.2.1.1) — it is NOT fanned
-- out to the user's connected resources. That breaks calls when the caller
-- has no presence info for the callee and addresses session-initiate to bare.
-- Fan it out ourselves: clone the stanza to each online resource and reply OK
-- to the caller so the default service-unavailable doesn't fire.
local function fan_out_jingle_to_resources(event)
	local stanza = event.stanza;
	if stanza.attr.type ~= "set" then return; end

	local jingle = stanza:find("{urn:xmpp:jingle:1}jingle");
	if not jingle or jingle.attr.action ~= "session-initiate" then return; end

	local to_user = jid.split(stanza.attr.to);
	local user = hosts[module.host].sessions[to_user];
	if not user or not user.sessions then return; end

	local routed = 0;
	for _, session in pairs(user.sessions) do
		if session.full_jid then
			local copy = st.clone(stanza);
			copy.attr.to = session.full_jid;
			module:send(copy);
			routed = routed + 1;
		end
	end

	if routed == 0 then return; end

	module:log("info", "Fanned out Jingle session-initiate from %s to %d resource(s) of %s",
		stanza.attr.from, routed, to_user);
	-- No explicit reply: the callee clients ack the routed IQ themselves
	-- (jingleManager.handleStanza always sends buildIQResult). Returning true
	-- halts processing so Prosody doesn't add a service-unavailable response.
	return true;
end

-- Priority 5 runs before the offline-push handler (priority 1) and before
-- Prosody's default service-unavailable response.
module:hook("iq/bare", fan_out_jingle_to_resources, 5);
