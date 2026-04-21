#!/bin/bash
set -e

IMAGE_NAME="ret2namespace_build"
CONTAINER_NAME="ret2namespace_temp"
BINARY_NAME="ret2namespace"
DIST_DIR="../dist"
LIBC243_DIR="/tmp/libc6_243/usr/lib/x86_64-linux-gnu"

echo "[+] Building Docker build image..."
docker build -t "$IMAGE_NAME" -f Dockerfile.build .

echo "[+] Creating temporary container..."
docker create --name "$CONTAINER_NAME" "$IMAGE_NAME" > /dev/null

echo "[+] Preparing dist directory..."
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

echo "[+] Copying binary..."
docker cp "$CONTAINER_NAME":/build/"$BINARY_NAME" "$DIST_DIR/$BINARY_NAME"

echo "[+] Copying glibc 2.43 libc + loader..."
cp "$LIBC243_DIR/libc.so.6" "$DIST_DIR/libc.so.6"
cp "$LIBC243_DIR/ld-linux-x86-64.so.2" "$DIST_DIR/ld-linux-x86-64.so.2"

echo "[+] Cleaning up..."
docker rm "$CONTAINER_NAME" > /dev/null

echo "[+] Done. Files available in $DIST_DIR:"
ls -lh "$DIST_DIR"
