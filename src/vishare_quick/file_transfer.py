"""Bounded, streaming file reception for authenticated Quick Share payloads.

Wire behavior
-------------
An Introduction declares each file with a payload id and a total size. Android
then sends ``PayloadTransferFrame`` DATA packets whose ``PayloadHeader.type`` is
FILE (2), whose ``PayloadHeader.id`` is the introduced id, and whose
``PayloadChunk.offset`` advances by exactly the number of bytes sent. The last
chunk carries ``PayloadChunk.flags & 1`` (LAST_CHUNK); documented senders either
put the final bytes in that chunk or send a zero-length terminator at
``offset == total_size``. NearDrop, NearShare, and squick-share all validate the
same invariants before writing.

Security properties
-------------------
* The peer-supplied name is reduced to a bare basename. Absolute paths,
  ``..`` segments, control characters, Windows device names, and invalid
  Windows characters cannot select or escape the download directory.
* Never overwrite: a unique name is chosen with an ``O_EXCL`` placeholder that
  is then atomically replaced by the completed file.
* Never buffer a whole file: bytes are streamed to a temporary file in the
  destination directory.
* A chunk may not exceed the declared size or skip ahead of the received
  offset. The transfer only succeeds when the received byte count equals the
  declared size at LAST_CHUNK.
* On any failure the temporary files are closed and removed. Received content
  is never executed or interpreted.
* There is no end-to-end cryptographic digest in the reviewed Introduction or
  payload schema. ``attachment_hash`` is an attachment identifier, not a
  content hash. Integrity verification is therefore the protocol's declared
  size plus strict chunk boundaries; a local SHA-256 is reported for the user,
  not claimed as peer verification.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import tempfile
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Callable

from vishare_quick.introduction import FileMetadata, Introduction

MAX_FILENAME_LENGTH = 200
MAX_SUFFIX_LENGTH = 24
DEFAULT_RESERVED_BYTES = 64 * 1024 * 1024  # keep headroom on the destination volume

_WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}
# C0/C1 controls, bidi overrides, and zero-width separators are unsafe in a
# terminal or filesystem name.
_UNSAFE_CHARS = re.compile(
    "[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069]"
)
_WINDOWS_INVALID = re.compile(r'[<>:"/\\|?*]')


class FileTransferError(Exception):
    """A protocol-level file transfer invariant was violated."""

    error_category = "invalid-payload-structure"


class FileTransferIOError(FileTransferError):
    """The local filesystem rejected or failed a transfer operation."""

    error_category = "local-implementation-error"


@dataclass(frozen=True)
class ReceivedFile:
    payload_id: int
    name: str
    path: Path
    size: int
    sha256: str
    integrity: str = "declared-size-and-chunk-boundaries"


@dataclass
class _Destination:
    metadata: FileMetadata
    display_name: str
    temp_path: Path
    handle: BinaryIO | None
    received: int = 0
    digest: "hashlib._Hash" = field(default_factory=hashlib.sha256)


def safe_filename(name: object, fallback: str = "received-file") -> str:
    """Return a bare, safe filename for any peer-supplied value.

    The result never contains a path separator, a control/format character, a
    Windows-invalid character, a reserved device name, or a leading/trailing
    dot. It is never used as a path by itself; callers join it to a resolved
    download directory and re-check the parent.
    """
    if not isinstance(name, str):
        return fallback
    # A Windows or Android peer may send either separator. Keep only the final
    # path component so absolute paths and traversal segments cannot survive.
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    base = "".join(
        character
        for character in base
        if unicodedata.category(character) not in {"Cc", "Cf"}
    )
    base = _UNSAFE_CHARS.sub("", base)
    base = _WINDOWS_INVALID.sub("_", base)
    base = " ".join(base.split())
    base = base.strip().strip(".")
    if base in {"", ".", ".."}:
        return fallback
    stem, suffix = os.path.splitext(base)
    # Windows reserves the component before the first dot: CON.txt and
    # CON.foo.bar are both the CON device.
    if base.split(".", 1)[0].upper() in _WINDOWS_RESERVED:
        base = "_" + base
        stem, suffix = os.path.splitext(base)
    if len(suffix) > MAX_SUFFIX_LENGTH:
        suffix = suffix[:MAX_SUFFIX_LENGTH]
        base = stem + suffix
    if len(base) > MAX_FILENAME_LENGTH:
        stem = stem[: max(1, MAX_FILENAME_LENGTH - len(suffix))]
        base = stem + suffix
    return base or fallback


def unique_destination(directory: Path, name: str) -> Path:
    """Choose a non-existing path inside ``directory`` without overwriting."""
    directory = directory.resolve()
    safe_name = safe_filename(name)
    candidate = directory / safe_name
    if candidate.parent.resolve() != directory:
        raise FileTransferIOError("Refusing to write outside the download directory.")
    stem, suffix = candidate.stem, candidate.suffix
    counter = 1
    while candidate.exists():
        candidate = directory / f"{stem} ({counter}){suffix}"
        if candidate.parent.resolve() != directory:  # defensive; cannot normally happen
            raise FileTransferIOError("Refusing to write outside the download directory.")
        counter += 1
        if counter > 10000:
            raise FileTransferIOError("Could not choose a unique destination filename.")
    return candidate


def check_free_space(
    directory: Path, required: int, reserved: int = DEFAULT_RESERVED_BYTES
) -> bool:
    """Best-effort declared-size check before asking the user."""
    try:
        usage = shutil.disk_usage(directory)
    except OSError:
        return True
    return required >= 0 and required + max(0, reserved) <= usage.free


def _create_placeholder(destination: Path) -> None:
    """Create an empty O_EXCL placeholder so a later replace never clobbers."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        fd = os.open(destination, flags, 0o600)
    except FileExistsError as exc:
        raise FileTransferIOError("Destination file appeared while finalizing.") from exc
    os.close(fd)


class FileReceiver:
    """Stream one Introduction's files to a download directory."""

    def __init__(
        self,
        download_dir: Path,
        introduction: Introduction,
        *,
        progress: Callable[[int, int, int], None] | None = None,
        reserved_bytes: int = DEFAULT_RESERVED_BYTES,
    ) -> None:
        self.download_dir = Path(download_dir)
        self.introduction = introduction
        self.progress = progress
        self.reserved_bytes = reserved_bytes
        self._destinations: dict[int, _Destination] = {}
        self._prepared = False
        self._finished: list[ReceivedFile] = []

    @property
    def total_bytes(self) -> int:
        return self.introduction.total_size

    @property
    def received_bytes(self) -> int:
        return sum(item.received for item in self._destinations.values())

    @property
    def finished(self) -> tuple[ReceivedFile, ...]:
        return tuple(self._finished)

    @property
    def pending_payload_ids(self) -> set[int]:
        return {
            payload_id
            for payload_id, item in self._destinations.items()
            if item.handle is not None
        }

    def prepare(self) -> None:
        """Create the download directory and one temp file per declared file."""
        if self._prepared:
            raise FileTransferError("FileReceiver was already prepared.")
        if not self.introduction.is_supported_file_transfer:
            raise FileTransferError("Introduction is not a supported plain file transfer.")
        try:
            self.download_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise FileTransferIOError("Could not create the download directory.") from exc
        for metadata in self.introduction.files:
            display_name = safe_filename(metadata.name)
            try:
                fd, temp_name = tempfile.mkstemp(
                    prefix=".vishare-partial-", suffix=".part", dir=self.download_dir
                )
                handle = os.fdopen(fd, "wb")
            except OSError as exc:
                self.abort()
                raise FileTransferIOError("Could not create a temporary file.") from exc
            self._destinations[metadata.payload_id] = _Destination(
                metadata=metadata,
                display_name=display_name,
                temp_path=Path(temp_name),
                handle=handle,
            )
        self._prepared = True

    def known_payload_id(self, payload_id: int) -> bool:
        return payload_id in self._destinations

    def write_chunk(
        self,
        payload_id: int,
        *,
        total_size: int,
        offset: int,
        body: bytes,
        is_last_chunk: bool,
    ) -> None:
        """Validate and append one authenticated FILE chunk."""
        if not self._prepared:
            raise FileTransferError("FileReceiver is not prepared.")
        destination = self._destinations.get(payload_id)
        if destination is None or destination.handle is None:
            raise FileTransferError(f"File payload ID {payload_id} is not an open introduction entry.")
        if total_size != destination.metadata.size:
            raise FileTransferError(
                f"Payload {payload_id} declares {total_size} bytes but the "
                f"Introduction declared {destination.metadata.size}."
            )
        if not isinstance(body, bytes):
            raise FileTransferError("Payload chunk body must be bytes.")
        if offset != destination.received:
            raise FileTransferError(
                f"Payload {payload_id} chunk offset {offset} does not match "
                f"the received offset {destination.received}."
            )
        end = offset + len(body)
        if end > destination.metadata.size:
            raise FileTransferError(
                f"Payload {payload_id} chunk ends at {end}, beyond the declared "
                f"size {destination.metadata.size}."
            )
        if body:
            try:
                destination.handle.write(body)
            except OSError as exc:
                raise FileTransferIOError("Writing the received file failed.") from exc
            destination.received = end
            destination.digest.update(body)
            if self.progress is not None:
                self.progress(payload_id, destination.received, destination.metadata.size)
        if is_last_chunk:
            if destination.received != destination.metadata.size:
                raise FileTransferError(
                    f"Payload {payload_id} ended at {destination.received} bytes, "
                    f"not the declared {destination.metadata.size}."
                )
            self._finalize(destination)
        # If the last data chunk omitted LAST_CHUNK, the documented senders
        # follow it with a zero-length terminator at offset == total_size. The
        # entry stays open until that terminator arrives; a chunk past the
        # declared size was already rejected above.

    def _finalize(self, destination: _Destination) -> None:
        handle = destination.handle
        assert handle is not None
        try:
            handle.flush()
            os.fsync(handle.fileno())
            handle.close()
        except OSError as exc:
            destination.handle = None
            raise FileTransferIOError("Flushing the received file failed.") from exc
        destination.handle = None
        destination_path = unique_destination(self.download_dir, destination.display_name)
        try:
            _create_placeholder(destination_path)
            os.replace(destination.temp_path, destination_path)
        except OSError as exc:
            try:
                destination_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise FileTransferIOError("Finalizing the received file failed.") from exc
        self._finished.append(
            ReceivedFile(
                payload_id=destination.metadata.payload_id,
                name=destination_path.name,
                path=destination_path,
                size=destination.metadata.size,
                sha256=destination.digest.hexdigest(),
            )
        )

    def abort(self) -> None:
        """Close and remove every unfinished temporary file. Idempotent."""
        for destination in self._destinations.values():
            if destination.handle is not None:
                try:
                    destination.handle.close()
                except OSError:
                    pass
                destination.handle = None
            try:
                destination.temp_path.unlink(missing_ok=True)
            except OSError:
                pass
        self._prepared = False
