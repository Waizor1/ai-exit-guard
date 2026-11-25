"""Emit the privileged helper's immutable host set from the Go worker's bundled catalog."""
from pathlib import Path
import re
import sys

CATALOG = Path(__file__).resolve().parents[2] / "internal/mcpdns/catalog.tsv"


def emit(output):
    names = [line.split("\t", 1)[0] for line in CATALOG.read_text().splitlines()
             if line and not line.startswith("#")]
    if (names != sorted(set(names)) or not 20 <= len(names) <= 16384
            or any(len(n) > 253 or not re.fullmatch(r"[a-z0-9.-]+", n) for n in names)):
        raise ValueError("Invalid MCP registry snapshot")
    output.write_text('let embeddedMCPHosts = Set("""\n' + "\n".join(names)
                      + '\n""".split(separator: "\\n").map(String.init))\n')


if __name__ == "__main__":
    emit(Path(sys.argv[1]))
