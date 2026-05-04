-- mod_report_log
--
-- Logs XEP-0377 (Spam Reporting) <report/> elements in two forms:
--   1. embedded inside XEP-0191 (Simple Communications Blocking) <block/> IQs
--   2. standalone, sent as a <message> stanza addressed to the offender
-- Block IQs continue to mod_blocklist (no consumption). Standalone report
-- messages ARE consumed after logging — otherwise the offender's client
-- would receive the report stanza, which leaks the reporter's identity.
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

local function log_message_report(event)
	local origin, stanza = event.origin, event.stanza;
	local report = stanza:get_child("report", REPORTING_NS);
	if not report then return; end

	local reporter = origin.full_jid or (origin.username and origin.host and (origin.username .. "@" .. origin.host)) or tostring(stanza.attr.from);
	local target = stanza.attr.to;
	local reason = reason_short(report.attr.reason);
	local text_node = report:get_child("text");
	local text = text_node and text_node:get_text() or nil;
	local stanza_id_node = report:get_child("stanza-id", "urn:xmpp:sid:0");
	local stanza_id = stanza_id_node and stanza_id_node.attr.id or nil;

	local entry = {
		ts = datetime.datetime(),
		reporter = reporter,
		target = target,
		reason = reason,
		text = text,
		stanza_id = stanza_id,
	};

	module:log("warn",
		"abuse-report (standalone) reporter=%s target=%s reason=%s stanza_id=%s",
		entry.reporter, entry.target, entry.reason, entry.stanza_id or "-");
	append_log(entry);
	-- Consume the stanza: don't route the report to the offender.
	return true;
end

-- Catch standalone report <message> stanzas before routing.
module:hook("pre-message/bare", log_message_report, 100);
module:hook("pre-message/full", log_message_report, 100);

module:log("info", "mod_report_log loaded, writing to %s", LOG_PATH);
