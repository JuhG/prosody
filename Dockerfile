FROM prosody/prosody:trunk

# lua-http (HTTP/2 client) + luaossl (ECDSA signing) for direct APNs VoIP push
RUN sed -i \
      's|http://deb.debian.org/debian|http://archive.debian.org/debian|g; \
       s|http://security.debian.org/debian-security|http://archive.debian.org/debian-security|g' \
      /etc/apt/sources.list && \
    sed -i '/buster-updates/d' /etc/apt/sources.list && \
    apt-get update && apt-get install -y --no-install-recommends \
      luarocks libssl-dev build-essential m4 liblua5.2-dev && \
    export C_INCLUDE_PATH=/usr/include/lua5.2 && \
    luarocks install luaossl LUA_INCDIR=/usr/include/lua5.2 && \
    luarocks install http LUA_INCDIR=/usr/include/lua5.2 && \
    rm -rf /var/lib/apt/lists/*

COPY prosody.cfg.lua /etc/prosody/prosody.cfg.lua
COPY mod_voip_push.lua /usr/lib/prosody/modules/mod_voip_push.lua
COPY www/ /var/www/prosody/

COPY entrypoint-fly.sh /entrypoint-fly.sh
RUN chmod +x /entrypoint-fly.sh

ENTRYPOINT ["/entrypoint-fly.sh"]
