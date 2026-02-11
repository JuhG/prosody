#!/bin/bash
set -e

# Fix volume ownership — Fly mounts as root, Prosody needs to write as prosody user
chown -R prosody:prosody /var/lib/prosody
chown prosody:prosody /var/run/prosody/

# Create test accounts if they don't exist
prosodyctl register user1 prosody.fly.dev password 2>/dev/null || true
prosodyctl register user2 prosody.fly.dev password 2>/dev/null || true
prosodyctl register user3 prosody.fly.dev password 2>/dev/null || true

# Start Prosody as the prosody user in foreground
exec setpriv --reuid=prosody --regid=prosody --init-groups prosody -F
