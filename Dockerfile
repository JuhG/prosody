FROM prosody/prosody:trunk

# lua-http (HTTP/2 client) + luaossl (ECDSA signing) for direct APNs VoIP push
RUN apt-get update && apt-get install -y --no-install-recommends \
      luarocks libssl-dev build-essential && \
    luarocks install luaossl && \
    luarocks install lua-http && \
    rm -rf /var/lib/apt/lists/*

COPY prosody.cfg.lua /etc/prosody/prosody.cfg.lua
COPY mod_voip_push.lua /usr/lib/prosody/modules/mod_voip_push.lua
COPY www/ /var/www/prosody/

COPY entrypoint-fly.sh /entrypoint-fly.sh
RUN chmod +x /entrypoint-fly.sh

ENTRYPOINT ["/entrypoint-fly.sh"]
