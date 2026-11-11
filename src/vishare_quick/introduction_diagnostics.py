"""Bounded diagnostics for the authenticated Quick Share Introduction.

This module is the bridge between the live paired-key response stage and the
pure :mod:`vishare_quick.introduction` parser. It deliberately performs no
protocol writes: parsing an Introduction is metadata inspection, not PIN
verification, identity verification, consent, or file acceptance.

The raw capture option exists only for protocol analysis. It writes the exact
decrypted sharing ``Frame`` body that the parser received, never UKEY2 keys,
SecureMessage envelopes, or certificates. Capture is opt-in, uses a fixed
predictable directory by default, refuses ``..`` directory components, never
uses a peer-supplied filename, and does not overwrite an existing file.
"""
from __future__ import annotations

import os
import secrets
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Callable

from vishare_quick.introduction import Introduction, IntroductionError, parse_introduction
from vishare_quick.protocol import (
    FrameError,
    FrameTimeout,
    PeerDisconnected,
    TruncatedFrame,
    read_frame,
)
from vishare_quick.protocol_timeline import ProtocolTimeline, safe_error_detail
from vishare_quick.secure_channel import (
    AuthenticatedFrameSummary,
    ReceiveKeys,
    SecureChannelError,
    authenticate_and_inspect_frame,
)

DEFAULT_CAPTURE_DIRECTORY = Path.home() / ".vishare-quick" / "introductions"
CAPTURE_FILENAME_PREFIX = "introduction-"
CAPTURE_FILENAME_SUFFIX = ".bin"
OBSERVATION_WINDOW_SECONDS = 5.0
MAX_OBSERVED_FRAMES = 16
_MAX_LOG_FILENAME_LENGTH = 120
_MAX_LOG_LABEL_LENGTH = 80
_MAX_LOGGED_LABELS = 12


class IntroductionCaptureError(ValueError):
    """A local raw Introduction capture could not be written safely."""


@dataclass(frozen=True)
class IntroductionDiagnosticsResult:
    """Outcome of parsing one authenticated Introduction.

    ``pin_verification`` is always ``not-attempted`` here. Keeping it explicit
    prevents callers from confusing a successful parse with a verified PIN or a
    verified peer identity.
    """

    introduction: Introduction | None
    parsed: bool
    error: str | None = None
    capture_path: Path | None = None
    capture_error: str | None = None
    pin_verification: str = "not-attempted"


@dataclass(frozen=True)
class IntroductionObservationResult:
    """Read-only result of watching the connection briefly after Introduction."""

    status: str
    frames_observed: int
    next_inbound_sequence: int
    last_offline_type: str | None = None


def _sanitize_text(value: object, max_length: int, *, replace_path_separators: bool) -> str:
    """Render untrusted peer text as one bounded, control-free line.

    ``str.split`` collapses all Unicode whitespace, which also removes newline
    and tab injection. Format/control/surrogate characters (Unicode categories
    ``C*``) are replaced rather than rendered, so a filename cannot contain a
    terminal escape or bidirectional override.
    """
    text = str(value)
    cleaned: list[str] = []
    for character in text:
        category = unicodedata.category(character)
        if category.startswith("C"):
            cleaned.append("?")
        elif replace_path_separators and character in "/\\":
            cleaned.append("_")
        else:
            cleaned.append(character)
    result = " ".join("".join(cleaned).split())
    if not result:
        return "<empty>"
    if len(result) > max_length:
        result = result[: max_length - 3] + "..."
    return result


def sanitize_filename_for_log(name: object) -> str:
    """Return a safe, bounded display form of a peer-supplied filename."""
    return _sanitize_text(
        name, _MAX_LOG_FILENAME_LENGTH, replace_path_separators=True
    )


def _safe_label(value: object) -> str:
    return _sanitize_text(
        value, _MAX_LOG_LABEL_LENGTH, replace_path_separators=False
    )


def _join_labels(values) -> str:
    unique = sorted({_safe_label(value) for value in values})
    if not unique:
        return "none"
    shown = unique[:_MAX_LOGGED_LABELS]
    if len(unique) > len(shown):
        shown.append(f"+{len(unique) - len(shown)} more")
    return ",".join(shown)


def _unsupported_families(introduction: Introduction) -> str:
    parts: list[str] = []
    if introduction.text_entries:
        parts.append(f"text({introduction.text_entries})")
    if introduction.wifi_credentials_entries:
        parts.append(
            f"wifi_credentials({introduction.wifi_credentials_entries})"
        )
    if introduction.app_entries:
        parts.append(f"app({introduction.app_entries})")
    if introduction.stream_entries:
        parts.append(f"stream({introduction.stream_entries})")
    return ",".join(parts) or "none"


def describe_introduction(
    introduction: Introduction, *, log_filenames: bool = False
) -> tuple[str, ...]:
    """Build safe, metadata-only diagnostic lines for a parsed Introduction.

    The transfer ID value is never rendered; only its presence is reported.
    Filenames and parent folders are omitted unless ``log_filenames`` is
    explicitly enabled, and then only sanitized names are shown.
    """
    file_types = _join_labels(item.type_name for item in introduction.files)
    mime_types = _join_labels(item.mime_type for item in introduction.files)
    transfer_id = "present" if introduction.transfer_id is not None else "absent"
    lines = [
        (
            f"Introduction parsed: files={len(introduction.files)}; "
            f"text_entries={introduction.text_entries}; "
            f"total_declared_size={introduction.total_size} bytes."
        ),
        f"  file_types={file_types}; mime_types={mime_types}.",
        (
            f"  start_transfer={str(introduction.start_transfer).lower()}; "
            f"transfer_id={transfer_id}; "
            f"continuation={str(introduction.continuation).lower()}; "
            f"expect_more={str(introduction.expect_more).lower()}; "
            "supported_file_transfer="
            f"{str(introduction.is_supported_file_transfer).lower()}."
        ),
        (
            "  unsupported_attachments="
            f"{_unsupported_families(introduction)}; "
            f"unknown_introduction_fields={len(introduction.unknown_field_numbers)}."
        ),
        (
            "  PIN verification: not performed. Introduction parsing is not "
            "PIN or identity verification."
        ),
    ]
    if log_filenames:
        for index, item in enumerate(introduction.files):
            lines.append(
                f"  file[{index}]: name={sanitize_filename_for_log(item.name)}; "
                f"type={item.type_name}; mime={_safe_label(item.mime_type)}; "
                f"size={item.size} bytes."
            )
    return tuple(lines)


def resolve_capture_directory(directory: str | os.PathLike[str] | None) -> Path:
    """Resolve an explicit capture directory or the predictable default.

    ``..`` components are rejected even though the directory is chosen locally:
    the capture flag must not become a path-traversal primitive if it is ever
    wired to a less trusted caller. Existing non-directories are refused early.
    """
    if directory is None:
        candidate = DEFAULT_CAPTURE_DIRECTORY
    else:
        text = os.fspath(directory)
        candidate = DEFAULT_CAPTURE_DIRECTORY if not text.strip() else Path(text).expanduser()
    # Both separator styles are checked so a Windows-style path stays rejected
    # when the same value is passed on a POSIX host, where "\" is not a
    # separator and would otherwise become part of a single file name.
    if any(part == ".." for part in candidate.parts) or any(
        part == ".." for part in PureWindowsPath(candidate).parts
    ):
        raise IntroductionCaptureError(
            "Introduction capture directory must not contain '..' components."
        )
    resolved = candidate.resolve(strict=False)
    if resolved.exists() and not resolved.is_dir():
        raise IntroductionCaptureError(
            "Introduction capture path exists and is not a directory."
        )
    return resolved


def _default_capture_filename() -> str:
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    return (
        f"{CAPTURE_FILENAME_PREFIX}{stamp}-{secrets.token_hex(4)}"
        f"{CAPTURE_FILENAME_SUFFIX}"
    )


def _validate_capture_filename(filename: str) -> None:
    if not isinstance(filename, str) or not filename:
        raise IntroductionCaptureError("Capture filename must be a non-empty string.")
    if filename in (".", ".."):
        raise IntroductionCaptureError("Capture filename is not a regular file name.")
    if "/" in filename or "\\" in filename or "\x00" in filename:
        raise IntroductionCaptureError(
            "Capture filename must not contain a path separator or NUL."
        )
    if Path(filename).name != filename:
        raise IntroductionCaptureError("Capture filename must be a plain file name.")
    if any(unicodedata.category(character).startswith("C") for character in filename):
        raise IntroductionCaptureError(
            "Capture filename must not contain control or format characters."
        )
    if len(filename) > 255:
        raise IntroductionCaptureError("Capture filename is too long.")


def save_introduction_capture(
    payload_body: bytes,
    directory: str | os.PathLike[str] | None = None,
    *,
    filename: str | None = None,
    overwrite: bool = False,
) -> Path:
    """Write the exact authenticated Introduction body and return its path.

    ``payload_body`` must be the complete decrypted sharing ``Frame`` (the
    ``AuthenticatedFrameSummary.payload_body`` value). It is never a key,
    certificate, or SecureMessage envelope. Existing files are not replaced
    unless ``overwrite=True`` is supplied explicitly by local code.
    """
    if not isinstance(payload_body, (bytes, bytearray, memoryview)):
        raise TypeError("payload_body must be bytes.")
    body = bytes(payload_body)
    if not body:
        raise IntroductionCaptureError("Refusing to save an empty Introduction body.")

    target_directory = resolve_capture_directory(directory)
    if filename is None:
        filename = _default_capture_filename()
    else:
        _validate_capture_filename(filename)
    target = target_directory / filename
    if target.parent.resolve(strict=False) != target_directory:
        raise IntroductionCaptureError("Capture path escapes the capture directory.")

    try:
        existed = target_directory.exists()
        target_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not existed:
            try:
                os.chmod(target_directory, 0o700)
            except OSError:
                pass
    except OSError as exc:
        raise IntroductionCaptureError(
            f"Could not create Introduction capture directory: {exc}"
        ) from exc

    mode = "wb" if overwrite else "xb"
    try:
        with open(target, mode) as handle:
            handle.write(body)
    except FileExistsError as exc:
        raise IntroductionCaptureError(
            "Capture file already exists; refusing to overwrite it."
        ) from exc
    except OSError as exc:
        raise IntroductionCaptureError(
            f"Could not write Introduction capture: {exc}"
        ) from exc
    try:
        os.chmod(target, 0o600)
    except OSError:
        pass
    return target


def _capture(
    payload_body: bytes,
    capture_directory: str | os.PathLike[str] | None,
    *,
    timeline: ProtocolTimeline | None,
    printer: Callable[[str], None],
) -> tuple[Path | None, str | None]:
    try:
        path = save_introduction_capture(payload_body, capture_directory)
    except IntroductionCaptureError as exc:
        detail = safe_error_detail(exc)
        if timeline is not None:
            timeline.event(
                "LOCAL", "INTRODUCTION_CAPTURE_FAILED", detail=detail
            )
        printer(f"WARNING: raw Introduction capture failed: {detail}")
        return None, detail
    if timeline is not None:
        timeline.event(
            "LOCAL", "INTRODUCTION_CAPTURED", bytes=len(payload_body)
        )
    printer(
        f"Raw Introduction body saved to {path} "
        "(may contain private sender and file metadata; keep it out of Git)."
    )
    return path, None


def handle_authenticated_introduction(
    summary: AuthenticatedFrameSummary,
    *,
    timeline: ProtocolTimeline | None = None,
    capture_directory: str | os.PathLike[str] | None = None,
    log_filenames: bool = False,
    printer: Callable[[str], None] = print,
) -> IntroductionDiagnosticsResult:
    """Parse one authenticated Introduction without sending or accepting anything.

    A parse error is returned as data rather than raised so the listener can
    report the failure and close cleanly. Capture, when requested, happens
    before parsing so a malformed body can still be preserved for analysis.
    """
    meta = summary.payload_transfer
    if summary.sharing_type != "INTRODUCTION":
        detail = (
            "Authenticated frame is not an Introduction "
            f"(sharing={summary.sharing_type or 'none'})."
        )
        if timeline is not None:
            timeline.state("INTRODUCTION_PARSE_FAILED")
            timeline.event("ERROR", "INTRODUCTION_PARSE_ERROR", detail=detail)
        printer(f"Introduction parse failed: {detail}")
        return IntroductionDiagnosticsResult(
            introduction=None, parsed=False, error=detail
        )
    if summary.payload_body is None:
        detail = "Authenticated Introduction carried no payload body."
        if timeline is not None:
            timeline.state("INTRODUCTION_PARSE_FAILED")
            timeline.event("ERROR", "INTRODUCTION_PARSE_ERROR", detail=detail)
        printer(f"Introduction parse failed: {detail}")
        return IntroductionDiagnosticsResult(
            introduction=None, parsed=False, error=detail
        )
    if meta is None or not meta.complete_sharing_frame:
        detail = (
            "Authenticated Introduction is not a complete BYTES payload; "
            "refusing to parse a partial frame."
        )
        if timeline is not None:
            timeline.state("INTRODUCTION_PARSE_FAILED")
            timeline.event("ERROR", "INTRODUCTION_PARSE_ERROR", detail=detail)
        printer(f"Introduction parse failed: {detail}")
        return IntroductionDiagnosticsResult(
            introduction=None, parsed=False, error=detail
        )

    payload_body = summary.payload_body
    capture_path: Path | None = None
    capture_error: str | None = None
    if capture_directory is not None:
        capture_path, capture_error = _capture(
            payload_body,
            capture_directory,
            timeline=timeline,
            printer=printer,
        )

    try:
        introduction = parse_introduction(payload_body)
    except IntroductionError as exc:
        detail = safe_error_detail(exc)
        if timeline is not None:
            timeline.state("INTRODUCTION_PARSE_FAILED")
            timeline.error(exc, stage="Introduction parsing")
        printer(f"Introduction parse failed: {detail}")
        printer(
            "No PIN verification, consent response, or file transfer was performed."
        )
        return IntroductionDiagnosticsResult(
            introduction=None,
            parsed=False,
            error=detail,
            capture_path=capture_path,
            capture_error=capture_error,
        )

    file_types = _join_labels(item.type_name for item in introduction.files)
    mime_types = _join_labels(item.mime_type for item in introduction.files)
    unsupported = _unsupported_families(introduction)
    transfer_id = "present" if introduction.transfer_id is not None else "absent"
    if timeline is not None:
        timeline.event(
            "IN",
            "INTRODUCTION",
            parsed=True,
            files=len(introduction.files),
            text=introduction.text_entries,
            total_bytes=introduction.total_size,
            file_types=file_types,
            mime_types=mime_types,
            start_transfer=introduction.start_transfer,
            transfer_id=transfer_id,
            continuation=introduction.continuation,
            expect_more=introduction.expect_more,
            unsupported=unsupported,
            supported_file_transfer=introduction.is_supported_file_transfer,
        )
        timeline.state("INTRODUCTION_PARSED")
    for line in describe_introduction(
        introduction, log_filenames=log_filenames
    ):
        printer(line)
    return IntroductionDiagnosticsResult(
        introduction=introduction,
        parsed=True,
        capture_path=capture_path,
        capture_error=capture_error,
    )


def observe_inbound(
    reader,
    receive_keys: ReceiveKeys,
    expected_sequence: int,
    *,
    timeline: ProtocolTimeline | None = None,
    max_frames: int = MAX_OBSERVED_FRAMES,
    printer: Callable[[str], None] = print,
    stage: str = "post-Introduction observation",
    frame_label: str = "Post-Introduction frame",
) -> IntroductionObservationResult:
    """Watch the authenticated connection read-only for a bounded frame count.

    This helper has no writer and therefore cannot send a PIN response, consent
    response, keep-alive acknowledgement, or any other protocol message. The
    caller bounds wall-clock time by supplying a reader with a deadline.

    ``stage`` and ``frame_label`` exist so the same read-only watcher can follow
    an Introduction or an alternate authenticated RESPONSE without implying that
    the latter was consented to.
    """
    if max_frames < 1:
        raise ValueError("max_frames must be at least 1.")
    observed = 0
    next_sequence = expected_sequence
    last_offline: str | None = None
    status = "frame-limit"
    while observed < max_frames:
        try:
            frame = read_frame(reader, classify=False)
        except FrameTimeout:
            status = "timeout"
            break
        except (PeerDisconnected, TruncatedFrame):
            status = "disconnected"
            break
        except FrameError as exc:
            if timeline is not None:
                timeline.error(exc, stage=stage)
            status = "frame-error"
            break
        except OSError:
            status = "socket-error"
            break

        try:
            summary = authenticate_and_inspect_frame(
                frame, receive_keys, expected_sequence=next_sequence
            )
        except (FrameError, SecureChannelError) as exc:
            if timeline is not None:
                timeline.inbound_secure_failure(
                    frame.declared_length,
                    stage=stage,
                    exc=exc,
                )
                timeline.error(exc, stage=stage)
            status = "authentication-error"
            break

        observed += 1
        next_sequence += 1
        last_offline = summary.offline_type
        if timeline is not None:
            timeline.inbound_authenticated(summary, stage=stage)
        printer(
            f"{frame_label} {observed}: sequence={summary.sequence}; "
            f"offline={summary.offline_type}; "
            f"sharing={summary.sharing_type or 'none'}; no response sent."
        )
        if summary.offline_type == "DISCONNECTION":
            status = "peer-disconnected"
            break
    return IntroductionObservationResult(
        status=status,
        frames_observed=observed,
        next_inbound_sequence=next_sequence,
        last_offline_type=last_offline,
    )


def observe_after_introduction(
    reader,
    receive_keys: ReceiveKeys,
    expected_sequence: int,
    *,
    timeline: ProtocolTimeline | None = None,
    max_frames: int = MAX_OBSERVED_FRAMES,
    printer: Callable[[str], None] = print,
) -> IntroductionObservationResult:
    """Backward-compatible Introduction-specific read-only observation."""
    return observe_inbound(
        reader,
        receive_keys,
        expected_sequence,
        timeline=timeline,
        max_frames=max_frames,
        printer=printer,
    )
