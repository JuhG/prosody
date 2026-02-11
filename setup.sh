#!/bin/bash

echo "Setting up Prosody XMPP server with WebSocket and MAM..."

# Stop and remove existing container if it exists
docker stop prosody 2>/dev/null
docker rm prosody 2>/dev/null

# Run Prosody container with custom config
docker run -d \
  --name prosody \
  -p 5280:5280 \
  -p 5222:5222 \
  -v $(pwd)/server/prosody.cfg.lua:/etc/prosody/prosody.cfg.lua:ro \
  prosody/prosody:trunk

echo "Waiting for Prosody to start..."
sleep 5

# Create users using the register command
echo "Creating users..."
docker exec prosody prosodyctl register user1 localhost password
docker exec prosody prosodyctl register user2 localhost password
docker exec prosody prosodyctl register user3 localhost password

echo ""
echo "✓ Prosody XMPP server is running"
echo "✓ WebSocket endpoint: ws://localhost:5280/xmpp-websocket"
echo "✓ Users created:"
echo "  - user1@localhost (password: password)"
echo "  - user2@localhost (password: password)"
echo "  - user3@localhost (password: password)"
echo ""
echo "To stop the server: docker stop prosody"
echo "To view logs: docker logs prosody"