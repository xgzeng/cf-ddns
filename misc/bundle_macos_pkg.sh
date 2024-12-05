#!/bin/bash

## create macos .pkg installation file

set -e

# Define variables
PKG_NAME="cf-ddns"
VERSION=$(grep '^version =' Cargo.toml | sed -E 's/version = "(.*)"/\1/')
IDENTIFIER="io.github.xgzeng.${PKG_NAME}"
BUILD_DIR="target"
PKG_DIR="${BUILD_DIR}/pkg"
SCRIPTS_DIR="${BUILD_DIR}/pkg-scripts"

# Build release
cargo build --release

# Clear previous package directories
rm -rf "${PKG_DIR}"
rm -rf "${SCRIPTS_DIR}"

# Create necessary directories
mkdir -p "${PKG_DIR}/usr/local/bin"
mkdir -p "${PKG_DIR}/Library/LaunchDaemons"
mkdir -p "${PKG_DIR}/etc"
mkdir -p "${SCRIPTS_DIR}"

# Copy files to package directory
cp target/release/cf-ddns "${PKG_DIR}/usr/local/bin"
cp misc/cf-ddns.plist "${PKG_DIR}/Library/LaunchDaemons/${IDENTIFIER}.plist"
cp debian/cf-ddns.yaml "${PKG_DIR}/etc/cf-ddns.yaml.template"

# Create postinstall script
cat << EOF > "${SCRIPTS_DIR}/postinstall"
#!/bin/bash
chown root:wheel /Library/LaunchDaemons/${IDENTIFIER}.plist
chmod 644 /Library/LaunchDaemons/${IDENTIFIER}.plist
launchctl load /Library/LaunchDaemons/${IDENTIFIER}.plist
if [ ! -f /etc/cf-ddns.yaml ]; then
   mv /etc/cf-ddns.yaml.template /etc/cf-ddns.yaml
   chown root:wheel /etc/cf-ddns.yaml
   chmod 600 /etc/cf-ddns.yaml
fi
EOF

chmod +x "${SCRIPTS_DIR}/postinstall"

# Build the package
pkgbuild --root "${PKG_DIR}" \
         --identifier "${IDENTIFIER}" \
         --version "${VERSION}" \
         --scripts "${SCRIPTS_DIR}" \
         "${BUILD_DIR}/${PKG_NAME}-${VERSION}.pkg"

echo "Package created at ${BUILD_DIR}/${PKG_NAME}-${VERSION}.pkg"

