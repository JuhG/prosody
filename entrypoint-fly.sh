#!/bin/bash
set -e

# Fix volume ownership — Fly mounts as root, Prosody needs to write as prosody user
chown -R prosody:prosody /var/lib/prosody

exec prosody -F
