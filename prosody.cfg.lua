-- Prosody Configuration for Fly.io XMPP server with WebSocket and MAM

modules_enabled = {
    -- Core messaging
    "roster";           -- Contact list management (XEP-0237)
    "saslauth";         -- Authentication
    "disco";            -- Service Discovery (XEP-0030)
    "carbons";          -- Message synchronization across devices (XEP-0280)
    "private";          -- Private XML Storage (XEP-0049)
    "mam";              -- Message Archive Management (XEP-0313)

    -- User profile and presence
    "vcard_legacy";     -- vCard support (XEP-0054)
    "vcard4";           -- vCard4 support (XEP-0292)
    "presence";         -- Presence management
    "ping";             -- XMPP Ping (XEP-0199)
    "version";          -- Software version

    -- User management
    "register";         -- In-Band Registration (XEP-0077)
    "blocklist";        -- Simple Communications Blocking (XEP-0191)

    -- Advanced features
    "pep";              -- Personal Eventing Protocol (XEP-0163)
    "pubsub";           -- Publish-Subscribe (XEP-0060)
    "http_file_share";  -- HTTP File Upload (XEP-0363)
    "csi_simple";       -- Client State Indication (XEP-0352)

    -- Connection methods
    "bosh";             -- BOSH connection manager
    "websocket";        -- WebSocket support

    -- Additional useful modules
    "limits";           -- Rate limiting
    "time";             -- Entity Time (XEP-0202)
    "lastactivity";     -- Last Activity (XEP-0012)
    "offline";          -- Offline message storage
    "announce";         -- Server announcements
    "watchregistrations"; -- Monitor new registrations
    "motd";             -- Message of the Day
    "legacyauth";       -- Legacy authentication support
    "http";             -- HTTP server
    "http_files";       -- Serve static files
    "adhoc";            -- Ad-Hoc Commands (XEP-0050)
    "admin_adhoc";      -- Admin commands via Ad-Hoc
    "groups";           -- Shared roster groups
    "server_contact_info"; -- Contact info (XEP-0157)
}

-- Authentication configuration
authentication = "internal_plain"
c2s_require_encryption = false  -- Fly terminates TLS, internal traffic is plain
s2s_require_encryption = false
s2s_secure_auth = false
allow_unencrypted_plain_auth = true

-- Trust connections behind Fly's TLS proxy
consider_bosh_secure = true
consider_websocket_secure = true
trusted_proxies = { "0.0.0.0/0" }

-- MAM Configuration
archive_expires_after = "never"
default_archive_policy = true
max_archive_query_results = 100

-- Allow registration
allow_registration = true

-- File sharing configuration
http_file_share_size_limit = 50*1024*1024 -- 50 MB
http_file_share_expire_after = 60 * 60 * 24 * 7 -- 7 days

-- Client state indication
csi_queue_size = 256

-- Rate limiting
limits = {
    c2s = {
        rate = "10kb/s";
        burst = "2s";
    };
}

-- HTTP configuration
http_external_url = "https://prosody.fly.dev/"
http_ports = { 5280 }
https_ports = {}  -- Fly terminates TLS for us
http_interfaces = { "0.0.0.0" }
cross_domain_websocket = true
cross_domain_bosh = true

-- Virtual host configuration
VirtualHost "prosody.fly.dev"

-- MUC (Multi-User Chat) Configuration
Component "conference.prosody.fly.dev" "muc"
    name = "Messagely Chat Rooms"
    restrict_room_creation = false
    max_history_messages = 100
