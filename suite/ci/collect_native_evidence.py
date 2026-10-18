"""Collect bounded text diagnostics, with an explicit truncation manifest."""
import json
from pathlib import Path
import sys

FILE_LIMIT = 2 * 1024 * 1024
TOTAL_LIMIT = 20 * 1024 * 1024
COUNT_LIMIT = 64


def collect(root, destination, file_limit=FILE_LIMIT, total_limit=TOTAL_LIMIT,
            count_limit=COUNT_LIMIT):
    root = Path(root).resolve()
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    # Accounting/input evidence precedes potentially large compiler and CTest logs.
    patterns = (
        "native-evidence/*.json", "native-evidence/submodules.txt",
        "native-evidence/inputs.log", "native-evidence/toolchain.log",
        "native-evidence/junit.xml", "build-native/CMakeCache.txt",
        "native-evidence/*.log", "build-native/Testing/Temporary/*.log",
        "build-native/Testing/Temporary/*.txt",
        "build-native/CMakeFiles/CMakeConfigureLog.yaml",
        "build-native/CMakeFiles/CMakeError.log",
        "build-native/CMakeFiles/CMakeOutput.log",
    )
    seen, records, used, count = set(), [], 0, 0
    for pattern in patterns:
        for source in sorted(root.glob(pattern)):
            relative = source.relative_to(root)
            if relative in seen:
                continue
            seen.add(relative)
            # Do not follow links outside the diagnostic tree, or upload binaries.
            if source.is_symlink() or not source.resolve().is_relative_to(root):
                continue
            if not source.is_file():
                continue
            size = source.stat().st_size
            limit = min(file_limit, total_limit - used)
            if count >= count_limit or limit <= 0:
                records.append({"path": str(relative), "bytes": size, "omitted": True})
                continue
            with source.open("rb") as handle:
                handle.seek(max(0, size - limit))
                data = handle.read(limit)
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            used += len(data)
            count += 1
            records.append({"path": str(relative), "bytes": size,
                            "retained_tail_bytes": len(data),
                            "truncated": len(data) < size})
    (destination / "manifest.json").write_text(json.dumps({
        "file_limit": file_limit, "total_limit": total_limit,
        "count_limit": count_limit, "retained_bytes": used, "files": records,
    }, indent=2) + "\n")


if __name__ == "__main__":
    collect(*sys.argv[1:])
