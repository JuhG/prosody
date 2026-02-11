FROM prosody/prosody:trunk

COPY prosody.cfg.lua /etc/prosody/prosody.cfg.lua

COPY entrypoint-fly.sh /entrypoint-fly.sh
RUN chmod +x /entrypoint-fly.sh

CMD ["/entrypoint-fly.sh"]
