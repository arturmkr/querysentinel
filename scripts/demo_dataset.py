"""Print the path to the verified LEGO dump, downloading it if needed."""

import hashlib
import shutil
import urllib.request
from pathlib import Path
from tempfile import NamedTemporaryFile

LEGO_URL = (
    "https://raw.githubusercontent.com/neondatabase/postgres-sample-dbs/"
    "b54cb67534bf20775803b181b7a1c6f573422161/lego.sql"
)
LEGO_SHA256 = "3d89b1f0f0bd3d3e41512bc36ec6ff96f5abe18154be53f4a56daefedc6fe7ac"


def _verify(path: Path) -> None:
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if digest != LEGO_SHA256:
        raise ValueError(f"{path} does not match the expected LEGO snapshot (SHA-256: {digest})")


def lego_dump(cache_dir: Path) -> Path:
    local_dump = Path("lego.sql")
    if local_dump.is_file():
        _verify(local_dump)
        return local_dump.resolve()
    path = cache_dir / "lego.sql"
    if path.is_file():
        _verify(path)
        return path.resolve()
    cache_dir.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile(dir=cache_dir, delete_on_close=False) as download:
        with urllib.request.urlopen(LEGO_URL, timeout=30) as response:
            shutil.copyfileobj(response, download)
        download.flush()
        temporary_path = Path(download.name)
        _verify(temporary_path)
        temporary_path.replace(path)
    return path.resolve()


if __name__ == "__main__":
    print(lego_dump(Path(".cache/querysentinel")))
