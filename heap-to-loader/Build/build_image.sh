#!/bin/bash
set -e

IMAGE_NAME="heap-to-loader_build"
CONTAINER_NAME="heap-to-loader_temp"
BINARY_NAME="heap-to-loader"
DIST_DIR="../dist"

echo "[+] Building Docker build image..."
docker build -t "$IMAGE_NAME" -f Dockerfile.build .

echo "[+] Creating temporary container..."
docker create --name "$CONTAINER_NAME" "$IMAGE_NAME" > /dev/null

echo "[+] Preparing dist directory..."
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

echo "[+] Copying binary..."
docker cp "$CONTAINER_NAME":/build/"$BINARY_NAME" "$DIST_DIR/$BINARY_NAME"

echo "[+] Copying libc.so.6..."
docker cp "$CONTAINER_NAME":/lib/x86_64-linux-gnu/libc.so.6 "$DIST_DIR/libc.so.6"

echo "[+] Copying loader (ld)..."
docker cp "$CONTAINER_NAME":/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 "$DIST_DIR/ld-linux-x86-64.so.2"

echo "[+] Cleaning up..."
docker rm "$CONTAINER_NAME" > /dev/null

echo "[+] Done. Files available in $DIST_DIR:"
ls -lh "$DIST_DIR"

