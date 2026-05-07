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

local APNS_KEY_PEM        = os.getenv("APNS_KEY");
local APNS_KEY_ID         = os.getenv("APNS_KEY_ID");
local APNS_KEY_PEM_SBX    = os.getenv("APNS_KEY_SANDBOX");
local APNS_KEY_ID_SBX     = os.getenv("APNS_KEY_ID_SANDBOX");
local APNS_TEAM_ID        = os.getenv("APNS_TEAM_ID");
local APNS_BUNDLE_ID      = os.getenv("APNS_BUNDLE_ID");

if not (APNS_KEY_PEM and APNS_KEY_ID and APNS_TEAM_ID and APNS_BUNDLE_ID) then
	module:log("error", "Missing APNS_KEY / APNS_KEY_ID / APNS_TEAM_ID / APNS_BUNDLE_ID env vars");
	return;
end

local apns_key_prod = assert(pkey.new(APNS_KEY_PEM));
local apns_key_sbx  = (APNS_KEY_PEM_SBX and APNS_KEY_ID_SBX) and pkey.new(APNS_KEY_PEM_SBX) or nil;
local token_store   = module:open_store("voip_tokens");
module:log("info", "mod_voip_push loaded, APNs team=%s prod_key=%s sandbox_key=%s bundle=%s",
	APNS_TEAM_ID, APNS_KEY_ID, APNS_KEY_ID_SBX or "(using prod key)", APNS_BUNDLE_ID);

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

-- APNs JWTs are valid for 1 hour; cache per key to avoid signing on every push
local jwt_cache_prod, jwt_cached_at_prod;
local jwt_cache_sbx,  jwt_cached_at_sbx;
local JWT_TTL = 55 * 60;

local function make_jwt(sandbox)
	local now    = os.time();
	local cache  = sandbox and jwt_cache_sbx  or jwt_cache_prod;
	local cached = sandbox and jwt_cached_at_sbx or jwt_cached_at_prod;
	if cache and (now - cached) < JWT_TTL then
		return cache;
	end
	local key_id  = (sandbox and APNS_KEY_ID_SBX) or APNS_KEY_ID;
	local key_obj = (sandbox and apns_key_sbx)     or apns_key_prod;
	local hdr = base64url(json.encode({ alg = "ES256", kid = key_id }));
	local pld = base64url(json.encode({ iss = APNS_TEAM_ID, iat = now }));
	local msg = hdr .. "." .. pld;
	local d   = openssl_digest.new("sha256");
	d:update(msg);
	local jwt = msg .. "." .. base64url(der_to_raw(key_obj:sign(d)));
	if sandbox then
		jwt_cache_sbx      = jwt;
		jwt_cached_at_sbx  = now;
	else
		jwt_cache_prod     = jwt;
		jwt_cached_at_prod = now;
	end
	return jwt;
end

local function shell_escape(s)
	return "'" .. s:gsub("'", "'\\''") .. "'";
end

-- Push payload contract (consumed by iOS CallKitProvider → XmppCallKitProvider
-- → web jingleManager):
--   callType = "xmpp"   (selector for the XMPP CallKit branch on iOS)
--   callId   = call session id (sid attribute of the offer <signal/>)
--   peerJid  = caller's BARE JID (`user@host`); never include a resource. Web
--              treats this as the peer's stable identity — full JID would leak
--              into UI state and cause routing mismatches on terminate.
--   peerName = caller's username (the local part of the bare JID), used for
--              CallKit's localizedCallerName and the in-app modal heading.
local function send_push(device_token, sandbox, call_id, caller_jid, caller_name)
	local payload = json.encode({
		aps      = {},
		callType = "xmpp",
		callId   = call_id,
		peerJid  = caller_jid,
		peerName = caller_name,
	});

	local jwt = make_jwt(sandbox);
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

-- Buffered session-initiate stanzas keyed by callee username. When the callee
-- is offline we send a VoIP push and stash the original IQ here; when the
-- callee's app launches and sends initial presence, we replay it routed to the
-- new full JID. Without this the callee auto-accepts via CallKit but never
-- receives the offer, so the call hangs on "Connecting…".
local pending_initiates = {};
local PENDING_TTL = 30;

-- Dedupe pushes by (callee, sid). The same session-initiate can reach this
-- module twice in normal operation: once via iq/bare (caller addressed bare
-- JID, fan-out hook clones to each resource) and again via iq/full when the
-- cloned stanza re-enters routing. Both would otherwise emit a push and the
-- callee's iOS would receive two VoIP pushes → two CallKit entries → user
-- ends one, the other rings until iOS times it out.
local recent_pushes = {};
local PUSH_DEDUPE_TTL = 10;

local function should_push(to_user, sid)
	local key = to_user .. "::" .. sid;
	local now = os.time();
	for k, exp in pairs(recent_pushes) do
		if exp < now then recent_pushes[k] = nil; end
	end
	if recent_pushes[key] then return false; end
	recent_pushes[key] = now + PUSH_DEDUPE_TTL;
	return true;
end

local SIGNAL_NS = "urn:messagely:v1:webrtc-signal";

local function handle_offer_signal(event)
	local stanza = event.stanza;
	if stanza.attr.type ~= "set" then return; end

	local signal = stanza:find("{" .. SIGNAL_NS .. "}signal");
	if not signal or signal.attr.kind ~= "offer" then return; end

	local to_user = jid.split(stanza.attr.to);
	module:log("info", "WebRTC offer from %s to %s", stanza.attr.from, stanza.attr.to);

	local sessions = hosts[module.host].sessions[to_user];
	local data = token_store:get(to_user);

	-- Always push when a token is registered, regardless of whether the user
	-- appears online. A stale "online" session (e.g. a zombie c2s after the
	-- real device killed the app) would otherwise mask the fact that the
	-- actual device needs to be woken via PushKit. The client decides what to
	-- do with the push: launch CallKit if the app was killed, or ignore it if
	-- the in-app UI is already handling the call from the routed XMPP IQ.
	if data and should_push(to_user, signal.attr.sid) then
		pending_initiates[to_user] = {
			stanza  = st.clone(stanza),
			expires = os.time() + PENDING_TTL,
		};
		module:log("info", "Sending VoIP push to %s (token: %s..., sandbox=%s, online=%s)",
			to_user, data.token:sub(1, 8), tostring(data.sandbox or false), tostring(sessions ~= nil));
		send_push(
			data.token,
			data.sandbox or false,
			signal.attr.sid,
			jid.bare(stanza.attr.from),
			jid.split(stanza.attr.from)
		);
	elseif data then
		module:log("info", "Skipping duplicate VoIP push for %s sid=%s", to_user, signal.attr.sid);
	elseif not sessions then
		module:log("warn", "No VoIP token stored for %s and user has no online sessions", to_user);
	end

	-- If the user has online sessions, fall through so default routing (or the
	-- bare-JID fan-out hook) delivers the IQ via XMPP. Only halt when we
	-- actually have nothing to route to — otherwise Prosody would reply
	-- service-unavailable to the caller.
	if sessions then
		return;
	end
	return true;
end

module:hook("iq/full", handle_offer_signal, 1);
module:hook("iq/bare", handle_offer_signal, 1);

-- Replay buffered offer signal when the callee's app comes online and sends
-- its initial presence. Routed to the resource that just bound — that's the
-- device the user just woke up via the VoIP push.
module:hook("presence/initial", function(event)
	local session = event.origin;
	local user = session and session.username;
	if not user then return; end

	local pending = pending_initiates[user];
	if not pending then return; end
	pending_initiates[user] = nil;

	if os.time() > pending.expires then
		module:log("info", "Buffered offer signal for %s expired, dropping", user);
		return;
	end

	local copy = st.clone(pending.stanza);
	copy.attr.to = session.full_jid;
	module:send(copy);
	module:log("info", "Replayed buffered offer signal to %s", session.full_jid);
end);

-- If the caller cancels (sends end signal) while the buffered offer is still
-- pending, drop the buffer so a stale offer doesn't pop up later when the
-- callee finally comes online.
local function drop_buffered_on_end(event)
	local stanza = event.stanza;
	if stanza.attr.type ~= "set" then return; end

	local signal = stanza:find("{" .. SIGNAL_NS .. "}signal");
	if not signal or signal.attr.kind ~= "end" then return; end

	local to_user = jid.split(stanza.attr.to);
	local pending = pending_initiates[to_user];
	if pending and pending.stanza:find("{" .. SIGNAL_NS .. "}signal").attr.sid == signal.attr.sid then
		pending_initiates[to_user] = nil;
		module:log("info", "Dropped buffered offer signal for %s (caller cancelled)", to_user);
	end
end

module:hook("iq/full", drop_buffered_on_end, 1);
module:hook("iq/bare", drop_buffered_on_end, 1);

-- An IQ to a bare JID with an unknown payload is normally answered by the
-- server with <service-unavailable/> (RFC 6121 §8.5.2.1.1) — it is NOT fanned
-- out to the user's connected resources. That breaks calls when the caller
-- has no presence info for the callee and addresses a signal to bare. Fan
-- offer/end signals out ourselves: clone the stanza to each online resource
-- and reply OK to the caller so the default service-unavailable doesn't
-- fire. Two kinds need this:
--   - "offer": caller may genuinely not know the callee's resource yet.
--   - "end":   caller cancelling an outgoing call before any answer locked
--             a peerFullJid. Without bare-JID fan-out for end, online
--             callees would only learn the call was cancelled via an
--             eventual ICE failure — slow and leaves CallKit ringing.
local function fan_out_signal_to_resources(event)
	local stanza = event.stanza;
	if stanza.attr.type ~= "set" then return; end

	local signal = stanza:find("{" .. SIGNAL_NS .. "}signal");
	if not signal then return; end
	local kind = signal.attr.kind;
	if kind ~= "offer" and kind ~= "end" then return; end

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

	module:log("info", "Fanned out %s signal from %s to %d resource(s) of %s",
		kind, stanza.attr.from, routed, to_user);
	-- No explicit reply: the callee clients ack the routed IQ themselves
	-- (voipManager.handleStanza always sends buildIqResult). Returning true
	-- halts processing so Prosody doesn't add a service-unavailable response.
	return true;
end

-- Priority 5 runs before the offline-push handler (priority 1) and before
-- Prosody's default service-unavailable response.
module:hook("iq/bare", fan_out_signal_to_resources, 5);
