#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$root"
version=$(awk -F '"' '/^version = / { print $2; exit }' Cargo.toml)
arch=$(uname -m)
case "$arch" in
    arm64) platform='Hardware::CPU.arm?' ;;
    x86_64) platform='Hardware::CPU.intel?' ;;
    *) printf 'Unsupported architecture: %s\n' "$arch" >&2; exit 1 ;;
esac

cargo build --release --locked "$@"
binary="$root/target/release/macan"
if ! /usr/bin/lipo -verify_arch "$arch" "$binary"; then
    printf 'The binary must target the same architecture as this Mac.\n' >&2
    exit 1
fi

dist="$root/dist"
tap="$dist/homebrew-macan"
archive="$dist/macan-$version-$arch.tar.gz"
mkdir -p "$tap/Formula"
stage=$(mktemp -d "$dist/.package.XXXXXX")
trap 'rm -rf "$stage"' EXIT
mkdir "$stage/macan-$version"
/usr/bin/install -m 755 "$binary" "$stage/macan-$version/macan"
/bin/cp README.md "$stage/macan-$version/README.md"
/usr/bin/tar -C "$stage" -czf "$stage/release.tar.gz" "macan-$version"
/bin/mv "$stage/release.tar.gz" "$archive"
checksum=$(/usr/bin/shasum -a 256 "$archive" | awk '{ print $1 }')
url=$(/usr/bin/ruby -ruri -e 'puts "file://" + URI::DEFAULT_PARSER.escape(ARGV.fetch(0))' "$archive")

cat > "$tap/Formula/macan.rb" <<FORMULA
class Macan < Formula
  desc "Classical CAN for macOS using gs_usb USB adapters"
  url "$url"
  version "$version"
  sha256 "$checksum"

  depends_on :macos

  def install
    odie "This package was built for macOS $arch" unless $platform
    bin.install "macan"
    bin.install_symlink bin/"macan" => "candump"
    bin.install_symlink bin/"macan" => "cansend"
    doc.install "README.md"
  end

  def caveats
    <<~EOS
      Start the system daemon at your CAN bitrate. For example:
        sudo #{opt_bin}/macan service install --bitrate 250000

      Then run macan status, candump can0 or cansend can0 from your user account.
      Before uninstalling the formula, run sudo #{opt_bin}/macan service uninstall.
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/macan --version")
    assert_match "Usage: candump", shell_output("#{bin}/candump --help")
  end
end
FORMULA

if [ ! -d "$tap/.git" ]; then
    git -C "$tap" init -q -b main
fi
git -C "$tap" add Formula/macan.rb
if ! git -C "$tap" diff --cached --quiet; then
    git -C "$tap" -c user.name=macan -c user.email=macan@localhost commit -qm "Package macan $version for $arch"
fi

printf '\nTap: %s\nArchive: %s\n\n' "$tap" "$archive"
printf 'brew tap --custom-remote local/macan "%s"\nbrew install local/macan/macan\n' "$tap"
