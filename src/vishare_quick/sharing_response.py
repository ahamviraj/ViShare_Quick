"""Safe presentation of a sharing-layer ``ConnectionResponseFrame``.

The parser in :mod:`vishare_quick.secure_channel` deliberately retains only the
documented status enum and occurrence counts. This module renders those fields
and nothing else: attachment-hash map keys, attachment details, stream metadata,
payload IDs, and payload bodies are never exposed.

A response is not consent by itself. Nothing here may be used to decide that a
transfer should proceed.
"""
from __future__ import annotations

from vishare_quick.secure_channel import ConnectionResponseMetadata

CONNECTION_RESPONSE_STATUS_NAMES = {
    0: "UNKNOWN",
    1: "ACCEPT",
    2: "REJECT",
    3: "NOT_ENOUGH_SPACE",
    4: "UNSUPPORTED_ATTACHMENT_TYPE",
    5: "TIMED_OUT",
}


def connection_response_status_name(status: int | None) -> str:
    """Return the schema enum name, ``absent``, or ``enumN`` for a future value."""
    if status is None:
        return "absent"
    return CONNECTION_RESPONSE_STATUS_NAMES.get(status, f"enum{status}")


def describe_connection_response(
    metadata: ConnectionResponseMetadata | None,
) -> str:
    """Render status and counts only, never map keys or attachment contents."""
    if metadata is None:
        return (
            "status=not-parsed; attachment_details=unknown; "
            "stream_metadata=unknown"
        )
    return (
        f"status={connection_response_status_name(metadata.status)}; "
        f"attachment_details={metadata.attachment_details_count}; "
        f"stream_metadata={metadata.stream_metadata_count}; "
        f"unknown_fields={len(metadata.unknown_field_numbers)}"
    )
