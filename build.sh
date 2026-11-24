#!/bin/bash
set -eu
identity=${DEVELOPER_ID_APPLICATION:-}
profile=${NOTARY_KEYCHAIN_PROFILE:-}
release=false
case "${1:-}" in
 --release) release=true ;;
 "") ;;
 *) echo "Usage: build.sh [--release]" >&2; exit 2 ;;
esac
if $release && [[ -z "$identity" || -z "${DEVELOPER_ID_INSTALLER:-}" || -z "$profile" ]]; then
 echo "Public release requires Developer ID Application, Developer ID Installer, and a notarization profile." >&2
 exit 1
fi
if [[ -n "$profile" && -z "$identity" ]]; then
 echo "Notarization requires DEVELOPER_ID_APPLICATION." >&2
 exit 1
fi
cd "$(dirname "$0")"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/image" "$stage/root/Library/PrivilegedHelperTools"
app="$stage/root/Applications/AI Exit Guard.app"
daemon="$stage/root/Library/PrivilegedHelperTools/local.aiexitguard.rules"
res="$app/Contents/Resources"
mkdir -p "$app/Contents/Helpers" "$app/Contents/MacOS" "$res" dist
for arch in arm64 x86_64; do
 goarch=$arch
 if [[ $arch == x86_64 ]]; then goarch=amd64; fi
 CGO_ENABLED=0 GOOS=darwin GOARCH=$goarch go build -trimpath -ldflags="-s -w" -o "$stage/guard-$arch" .
 xcrun swiftc -O -target "$arch-apple-macos13.0" GuardRules.swift packaging/helper/main.swift -o "$stage/rules-$arch"
 xcrun swiftc -O -target "$arch-apple-macos13.0" packaging/TraceProbe.swift -o "$stage/trace-$arch"
 xcrun swiftc -O -target "$arch-apple-macos13.0" main.swift GuardRules.swift KillSwitch.swift Connections.swift RuntimePAC.swift ProxyClient.swift Panel.swift Recommendation.swift ExitHistory.swift -o "$stage/menu-$arch"
done
lipo -create "$stage"/rules-* -output "$daemon"
lipo -create "$stage"/trace-* -output "$app/Contents/Helpers/TraceProbe"
lipo -create "$stage"/guard-* -output "$res/guard"
lipo -create "$stage"/menu-* -output "$app/Contents/MacOS/AIExitGuard"
mkdir "$stage/Guard.iconset"
xcrun swift packaging/Icon.swift "$stage/Guard.iconset"
iconutil -c icns "$stage/Guard.iconset" -o "$res/Guard.icns"
for client in codex claude antigravity; do
 install -m 755 packaging/guarded-client "$res/guarded-$client"
done
cp Инструкция.txt packaging/*.command "$res/"
cp Info.plist "$app/Contents/Info.plist"
sign=(--force --options runtime --sign "${identity:--}")
if [[ -n "$identity" ]]; then sign+=(--timestamp); fi
codesign "${sign[@]}" "$daemon"
codesign "${sign[@]}" "$app/Contents/Helpers/TraceProbe"
codesign "${sign[@]}" "$res/guard"
codesign "${sign[@]}" "$app"
codesign --verify --strict --deep "$app"
python3 packaging/helper_package.py "$stage/root"
pkgbuild --analyze --root "$stage/root" "$stage/components.plist"
python3 - "$stage/components.plist" <<'PKG'
import plistlib, pathlib, sys
path = pathlib.Path(sys.argv[1])
components = plistlib.loads(path.read_bytes())
for component in components:
    component["BundleIsRelocatable"] = False
path.write_bytes(plistlib.dumps(components))
PKG
installer_sign=()
if [[ -n "${DEVELOPER_ID_INSTALLER:-}" ]]; then installer_sign=(--sign "$DEVELOPER_ID_INSTALLER"); fi
if [[ -n "$profile" && -z "${DEVELOPER_ID_INSTALLER:-}" ]]; then
 echo "Notarizing the installer requires DEVELOPER_ID_INSTALLER." >&2; exit 1
fi
version=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' Info.plist)
pkgbuild --root "$stage/root" --ownership recommended --install-location / \
 --component-plist "$stage/components.plist" --scripts packaging/installer \
 --identifier local.aiexitguard.installer --version "$version" ${installer_sign[@]+"${installer_sign[@]}"} "$stage/image/AI Exit Guard.pkg"
if [[ -n "$profile" ]]; then
 pkg="$stage/image/AI Exit Guard.pkg"
 xcrun notarytool submit "$pkg" --keychain-profile "$profile" --wait
 xcrun stapler staple "$pkg"
 xcrun stapler validate "$pkg"
 spctl --assess --type install "$pkg"
fi
hdiutil create -quiet -format UDZO -fs HFS+ -volname 'AI Exit Guard' -srcfolder "$stage/image" "$stage/package.dmg"
if [[ -n "$identity" ]]; then
 codesign --force --timestamp --sign "$identity" "$stage/package.dmg"
fi
if [[ -n "$profile" ]]; then
 xcrun notarytool submit "$stage/package.dmg" --keychain-profile "$profile" --wait
 xcrun stapler staple "$stage/package.dmg"
 xcrun stapler validate "$stage/package.dmg"
fi
hdiutil verify "$stage/package.dmg"
mv "$stage/package.dmg" "dist/AI Exit Guard.dmg"
