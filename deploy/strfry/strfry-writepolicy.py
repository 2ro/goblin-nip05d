#!/usr/bin/env python3
"""strfry write-policy plugin: restrict stored event kinds.

strfry streams one JSON request per line on stdin and expects one JSON reply
per line on stdout (https://github.com/hoytech/strfry/blob/master/docs/plugins.md).
We accept only the kinds the Goblin wallet uses and reject everything else at
ingest, keeping the relay lean and spam-resistant. Read-side behaviour is
untouched — this only governs what gets written.

The set mirrors the relay's purpose:
    0      profile metadata
    3      contact list
    5      event deletion (NIP-09)
    1059   gift wrap (NIP-59, private payments)
    10002  relay list metadata (NIP-65)
    10050  preferred DM relays (NIP-17)
"""

import json
import sys

ALLOWED_KINDS = {0, 3, 5, 1059, 10002, 10050}


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except ValueError:
            # Unparseable input: fail closed, but we have no id to echo.
            sys.stdout.write(
                json.dumps({"id": "", "action": "reject", "msg": "bad plugin input"})
                + "\n"
            )
            sys.stdout.flush()
            continue

        event = req.get("event", {})
        event_id = event.get("id", "")

        # Only "new" events are subject to the kind policy; pass through any
        # other request type (e.g. sync look-back) unchanged.
        if req.get("type") == "new" and event.get("kind") not in ALLOWED_KINDS:
            reply = {
                "id": event_id,
                "action": "reject",
                "msg": "blocked: event kind not accepted by this relay",
            }
        else:
            reply = {"id": event_id, "action": "accept", "msg": ""}

        sys.stdout.write(json.dumps(reply) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
