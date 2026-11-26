#!/usr/bin/env python3
"""Machine-readable bridge between AI Exit Guard and the vendored Antigravity patcher.

Usage: bridge.py <status|patch|restore> <language_server-path> <patcher.py>

The patcher is the MIT-licensed QNIX-Dev eligibility patcher (see
LICENSE.antigravity-patcher). This bridge only turns its human output into one
JSON line so the Go helper can report state to the menu app:

    {"state": "patched"|"unpatched"|"unsupported"|"missing"|"unknown"|"error",
     "rc": 0, "detail": "..."}

It never raises: every failure is reported in the JSON object.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import sys


def load(path):
    spec = importlib.util.spec_from_file_location("antigravity_patcher", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("patcher module not loadable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def state_of(module, path):
    status_fn = module.SPEC["manager"]["status"]
    try:
        return status_fn(path)[0]
    except LookupError:
        return "unsupported"
    except OSError:
        return "unknown"


def main(argv):
    if len(argv) != 3:
        print(json.dumps({"state": "error", "rc": 2, "detail": "usage: bridge.py action target patcher"}))
        return 0
    action, target, patcher = argv
    log = io.StringIO()
    state = "unknown"
    rc = 0
    try:
        module = load(patcher)
        if not os.path.isfile(target):
            print(json.dumps({"state": "missing", "rc": 0, "detail": ""}))
            return 0
        with contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
            if action == "status":
                state = state_of(module, target)
            elif action == "patch":
                rc = module.run("patch", ["manager"], {"manager": target},
                                macos_disable_library_validation=True)
                state = state_of(module, target)
            elif action == "restore":
                rc = module.run("restore", ["manager"], {"manager": target})
                state = state_of(module, target)
                # The upstream patcher keeps *.agybak inside the bundle. An extra
                # unsealed file makes macOS reject the restored original
                # signature, so drop it once the binary is restored and restore
                # the signature again.
                if state == "unpatched":
                    backup = target + module.BAK
                    if os.path.exists(backup):
                        try:
                            os.remove(backup)
                        except OSError:
                            pass
                    app = module._mac_app_bundle(target)
                    if rc != 0 and app:
                        module._mac_restore_bundle_signature(app)
                        rc = 0
                state = state_of(module, target)
            else:
                raise ValueError("unknown action: " + action)
    except Exception as exc:  # noqa: BLE001 - the app needs a report, not a traceback
        rc = 1
        log.write("\n" + str(exc))
    detail = " ".join(line.strip() for line in log.getvalue().splitlines() if line.strip())
    if len(detail) > 600:
        detail = detail[-600:]
    print(json.dumps({"state": state, "rc": rc, "detail": detail}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
