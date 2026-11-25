#!/bin/bash
set -eu
identity=${DEVELOPER_ID_APPLICATION:-}
profile=${NOTARY_KEYCHAIN_PROFILE:-}
local_sign=false
release=false
app_update=false
case "${1:-}" in
 --local-install) local_sign=true ;;
 --local-update) local_sign=true; app_update=true ;;
 --release) release=true ;;
 --app-update) app_update=true ;;
 "") ;;
 *) echo "Usage: build.sh [--release | --app-update | --local-install | --local-update]" >&2; exit 2 ;;
esac
if $release && [[ -z "$identity" || -z "${DEVELOPER_ID_INSTALLER:-}" || -z "$profile" ]]; then
 echo "Public release requires Developer ID Application, Developer ID Installer, and a notarization profile." >&2
 exit 1
fi
if $local_sign; then
 identity=${GUARD_LOCAL_CERT_SHA1:-}
 if [[ ! "$identity" =~ ^[a-fA-F0-9]{40}$ || ! -f "${GUARD_LOCAL_KEYCHAIN:-}" ]]; then
  echo "Local signing requires GUARD_LOCAL_CERT_SHA1 and GUARD_LOCAL_KEYCHAIN." >&2
  exit 1
 fi
 profile=""
 unset DEVELOPER_ID_INSTALLER
fi
if $app_update && ! $local_sign && [[ -z "$identity" || -z "$profile" ]]; then
 echo "An app update requires Developer ID Application and a notarization profile." >&2
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
python3 packaging/helper/catalog_source.py "$stage/MCPCatalog.swift"
for arch in arm64 x86_64; do
 goarch=$arch
 if [[ $arch == x86_64 ]]; then goarch=amd64; fi
 CGO_ENABLED=0 GOOS=darwin GOARCH=$goarch go build -trimpath -ldflags="-s -w" -o "$stage/guard-$arch" .
 xcrun swiftc -O -target "$arch-apple-macos13.0" GuardRules.swift "$stage/MCPCatalog.swift" packaging/helper/main.swift -o "$stage/rules-$arch"
 xcrun swiftc -O -target "$arch-apple-macos13.0" packaging/TraceProbe.swift -o "$stage/trace-$arch"
 xcrun swiftc -O -target "$arch-apple-macos13.0" main.swift MCPDNS.swift SystemDNS.swift GuardRules.swift KillSwitch.swift Connections.swift RuntimePAC.swift ProxyClient.swift Panel.swift Recommendation.swift ExitHistory.swift -o "$stage/menu-$arch"
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
install -m 755 packaging/guarded-client "$res/agy"
cp Инструкция.txt packaging/*.command "$res/"
cp Info.plist "$app/Contents/Info.plist"
sign=(--force --options runtime --sign "${identity:--}")
if $local_sign; then
 sign+=(--keychain "$GUARD_LOCAL_KEYCHAIN" --timestamp=none)
elif [[ -n "$identity" ]]; then
 sign+=(--timestamp)
fi
codesign "${sign[@]}" "$daemon"
codesign "${sign[@]}" "$app/Contents/Helpers/TraceProbe"
codesign "${sign[@]}" "$res/guard"
if $local_sign; then
 codesign "${sign[@]}" -r "=designated => identifier \"local.aiexitguard.menu\" and certificate leaf = H\"$identity\"" "$app"
else
 codesign "${sign[@]}" "$app"
fi
codesign --verify --strict --deep "$app"
install -m 755 "$res/guard" "$stage/root/Library/PrivilegedHelperTools/local.aiexitguard.ingress"
if $local_sign; then
 python3 packaging/helper_package.py "$stage/root" --local-cert "$identity"
elif $release || $app_update; then
 python3 packaging/helper_package.py "$stage/root" --developer-id
else
 python3 packaging/helper_package.py "$stage/root"
fi
if $app_update; then
 archive="$stage/AI Exit Guard.zip"
 ditto -c -k --keepParent "$app" "$archive"
 if $local_sign; then
  mv "$archive" "dist/AI Exit Guard Local Update.zip"
  exit 0
 fi
 xcrun notarytool submit "$archive" --keychain-profile "$profile" --wait
 xcrun stapler staple "$app"
 xcrun stapler validate "$app"
 spctl --assess --type execute "$app"
 ditto -c -k --keepParent "$app" "$stage/stapled.zip"
 mv "$stage/stapled.zip" "dist/AI Exit Guard App Update.zip"
 exit 0
fi
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
if [[ -n "$identity" ]] && ! $local_sign; then
 codesign --force --timestamp --sign "$identity" "$stage/package.dmg"
fi
if [[ -n "$profile" ]]; then
 xcrun notarytool submit "$stage/package.dmg" --keychain-profile "$profile" --wait
 xcrun stapler staple "$stage/package.dmg"
 xcrun stapler validate "$stage/package.dmg"
fi
hdiutil verify "$stage/package.dmg"
if $local_sign; then
 mv "$stage/package.dmg" "dist/AI Exit Guard Local Install.dmg"
else
 mv "$stage/package.dmg" "dist/AI Exit Guard.dmg"
fi
