#!/bin/bash
echo "[*] Building all components..."
make -C Auth-Server clean && make -C Auth-Server
make -C Chat-Server clean && make -C Chat-Server
make -C Client-server clean && make -C Client-server

echo "[*] Killing old processes..."
pkill -f auth-server
pkill -f chat-server
pkill -f client-server
sleep 1

echo "[*] Starting Auth-Server..."
./Auth-Server/auth-server &

echo "[*] Starting Chat-Server..."
./Chat-Server/chat-server &

sleep 1

echo "[*] Starting Client..."
./Client-server/client-server
