-- mod_report_log
--
-- Logs XEP-0377 (Spam Reporting) <report/> elements that are embedded inside
-- XEP-0191 (Simple Communications Blocking) <block/> requests. Does NOT
-- consume the event — mod_blocklist still processes the block normally.
--
-- Output goes to prosody's standard log (level "warn" so it stands out) plus
-- an append-only JSON-lines file at /var/log/prosody/abuse-reports.jsonl.
-- The JSONL file is what we point Apple at as evidence reports are recorded.

local json = require "util.json";
local datetime = require "util.datetime";

local BLOCKING_NS = "urn:xmpp:blocking";
local REPORTING_NS = "urn:xmpp:reporting:1";

local LOG_PATH = os.getenv("ABUSE_REPORT_LOG") or "/var/log/prosody/abuse-reports.jsonl";

local function append_log(entry)
	local f, err = io.open(LOG_PATH, "a");
	if not f then
		module:log("error", "mod_report_log: cannot open %s: %s", LOG_PATH, tostring(err));
		return;
	end
	f:write(json.encode(entry), "\n");
	f:close();
end

local function reason_short(uri)
	if not uri then return nil; end
	-- "urn:xmpp:reporting:abuse" -> "abuse"
	return uri:match("^urn:xmpp:reporting:(.+)$") or uri;
end

module:hook("iq-set/self/" .. BLOCKING_NS .. ":block", function(event)
	local origin, stanza = event.origin, event.stanza;
	local block = stanza:get_child("block", BLOCKING_NS);
	if not block then return; end

	for item in block:childtags("item") do
		local report = item:get_child("report", REPORTING_NS);
		if report then
			local target = item.attr.jid;
			local reason = reason_short(report.attr.reason);
			local text_node = report:get_child("text");
			local text = text_node and text_node:get_text() or nil;

			local entry = {
				ts = datetime.datetime(),
				reporter = origin.full_jid or (origin.username .. "@" .. origin.host),
				target = target,
				reason = reason,
				text = text,
			};

			module:log("warn",
				"abuse-report reporter=%s target=%s reason=%s",
				entry.reporter, entry.target, entry.reason);
			append_log(entry);
		end
	end
	-- intentionally no return — let mod_blocklist handle the block
end, 100); -- priority 100 = runs before mod_blocklist (default 0)

module:log("info", "mod_report_log loaded, writing to %s", LOG_PATH);
