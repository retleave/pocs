#!/bin/bash
set -euo pipefail

# Build nsjail
git clone https://github.com/google/nsjail.git nsjail_build
cd nsjail_build && git checkout 3.1
sed -i 's/^LDFLAGS\(.*\)/LDFLAGS\1 -static/' Makefile
make && mv nsjail ../ && strip ../nsjail
cd ../ && rm -rf nsjail_build

# Build everything in a private mount namespace (host safety)
unshare -m --propagation private bash << 'OUTER'
set -euo pipefail

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

IMG="rootfs.qcow2"
RAW="rootfs.raw"
MNT="/mnt/alpine"

EXP="exploit"
MOD="session.ko"
NSJAIL="nsjail"

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
ALPINE_URL="https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/x86_64/alpine-minirootfs-3.19.1-x86_64.tar.gz"

# ------------------------------------------------------------
# Raw image creation
# ------------------------------------------------------------

echo "[*] Creating raw image (2G)"
dd if=/dev/zero of="$RAW" bs=1M count=2048 status=none

LOOP="$(losetup -f --show "$RAW")"
mkfs.ext4 -F "$LOOP" > /dev/null

mkdir -p "$MNT"
mount "$LOOP" "$MNT"

# ------------------------------------------------------------
# Alpine rootfs install
# ------------------------------------------------------------

cd /tmp
wget -q "$ALPINE_URL"
tar -xzf "$(basename "$ALPINE_URL")" -C "$MNT"

echo "nameserver 8.8.8.8" > "$MNT/etc/resolv.conf"

# ------------------------------------------------------------
# Copy payloads
# ------------------------------------------------------------

mkdir -p "$MNT/usr/bin" "$MNT/opt"
cp "$BASE_DIR/$EXP"    "$MNT/usr/bin/exploit"
cp "$BASE_DIR/$NSJAIL" "$MNT/usr/bin/nsjail"
cp "$BASE_DIR/$MOD"    "$MNT/opt/session.ko"

# ------------------------------------------------------------
# Pseudo-filesystems (for chroot only)
# ------------------------------------------------------------

mount -t proc proc "$MNT/proc"
mount --rbind /sys "$MNT/sys"
mount --make-rprivate "$MNT/sys"
mount --rbind /dev "$MNT/dev"
mount --make-rprivate "$MNT/dev"

# ------------------------------------------------------------
# Chroot configuration
# ------------------------------------------------------------

chroot "$MNT" /bin/sh << 'EOF'
set -e

# --------------------------------------------------
# Base system
# --------------------------------------------------

apk update
apk add \
  busybox \
  busybox-openrc \
  busybox-suid \
  openrc \
  dhcpcd \
  mdevd-openrc \
  bash \
  util-linux \
  kmod

echo "HostPoc" > /etc/hostname

# --------------------------------------------------
# OpenRC minimal setup
# --------------------------------------------------

rc-update add bootmisc boot
rc-update add dhcpcd boot
rc-update add hostname boot
rc-update add hwclock boot
rc-update add modules boot
rc-update add sysctl boot
rc-update add syslog boot

rc-update add cgroups sysinit
rc-update add devfs sysinit
rc-update add mdevd sysinit

# --------------------------------------------------
# User setup
# --------------------------------------------------

addgroup -g 1000 user
adduser -u 1000 -G user -h /home/user -s /bin/bash -D user
echo "user:password1" | chpasswd

# --------------------------------------------------
# Bash prompt
# --------------------------------------------------

cat > /root/.bashrc << 'PROFILE'
if [ "$(id -u)" -eq 0 ]; then
  PS1='\033[1;31m\u@\h\033[0m:\033[33m\w\033[0m# '
else
  PS1='\033[1;32m\u@\h\033[0m:\033[36m\w\033[0m$ '
fi
PROFILE

# --------------------------------------------------
# Flag
# --------------------------------------------------

echo "llr{container_escape_msg_to_krop}" > /root/flag
chmod 400 /root/flag

# --------------------------------------------------
# Container filesystem
# --------------------------------------------------

mkdir -p /container
cp -a /bin /lib /usr /etc /home /opt /container/

mkdir -p /container/proc /container/dev
cp /root/.bashrc /container/home/user/.bashrc
echo "ContainerPoc" > /container/etc/hostname

# --------------------------------------------------
# Kernel module loading (rootfs-safe)
# --------------------------------------------------

# mdev rule for /dev/session
echo 'session root:user 0666' >> /etc/mdev.conf

# Load custom module once at boot
mkdir -p /etc/local.d
cat > /etc/local.d/session.start << 'MOD'
#!/bin/sh
# Explicit module load (no /lib/modules tree)
insmod /opt/session.ko 2>/dev/null || true
MOD

chmod +x /etc/local.d/session.start
rc-update add local default

# --------------------------------------------------
# nsjail configuration
# --------------------------------------------------

mkdir -p /etc/nsjail

cat > /etc/nsjail/nsjail.conf << 'NSJAIL'
name: "nsjail-config"
description: "nsjail config"

mode: ONCE
log_level: ERROR

hostname: "ContainerPoc"
cwd: "/home/user"

rlimit_as_type: HARD
rlimit_cpu_type: HARD
rlimit_nofile_type: HARD
rlimit_nproc_type: HARD

clone_newuts: true
disable_no_new_privs: true
clone_newnet: false

uidmap: [
  { inside_id: "1000", outside_id: "1000", count: 1 },
  { inside_id: "0",    outside_id: "0",    count: 1 }
]

gidmap: [
  { inside_id: "1000", outside_id: "1000", count: 1 },
  { inside_id: "0",    outside_id: "0",    count: 1 }
]

mount: [
  { src: "/container", dst: "/", is_bind: true, rw: true },
  { dst: "/proc", fstype: "proc", rw: false, nosuid: true, nodev: true, noexec: true },
  { dst: "/dev",  fstype: "tmpfs", rw: true, nosuid: true,
    options: "size=65536k,mode=755,uid=0,gid=0" },
  { src: "/dev/null",    dst: "/dev/null",    is_bind: true, rw: true },
  { src: "/dev/session", dst: "/dev/session", is_bind: true, rw: true }
]

exec_bin {
  path: "/bin/bash"
  arg0: "bash"
  arg: "-i"
}
NSJAIL

# --------------------------------------------------
# Auto-jail on login
# --------------------------------------------------

cat > /usr/bin/jail << 'JAIL'
#!/bin/sh
echo "[*] Entering container..."
/usr/bin/nsjail --config /etc/nsjail/nsjail.conf
/bin/bash -i
JAIL

chmod +x /usr/bin/jail
echo "ttyS0::respawn:/usr/bin/jail" >> /etc/inittab

sed -i 's|^root:.*:/bin/ash$|root:x:0:0:root:/root:/usr/bin/jail|' /etc/passwd

EOF

# ------------------------------------------------------------
# Cleanup
# ------------------------------------------------------------

umount -l "$MNT/proc" || true
umount -l "$MNT/sys"  || true
umount -l "$MNT/dev"  || true
umount -l "$MNT"      || true
losetup -d "$LOOP"

# ------------------------------------------------------------
# Convert to qcow2
# ------------------------------------------------------------

qemu-img convert -f raw -O qcow2 -c "$BASE_DIR/$RAW" "$BASE_DIR/$IMG"
rm -f "$BASE_DIR/$RAW"

echo "[+] Rootfs ready: $IMG"

OUTER