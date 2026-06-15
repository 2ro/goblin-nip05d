#!/usr/bin/env python3
"""strfry write-policy plugin: restrict stored event kinds.

strfry streams one JSON request per line on stdin and expects one JSON reply
per line on stdout (https://github.com/hoytech/strfry/blob/master/docs/plugins.md).
We accept only the kinds the Goblin wallet uses and reject everything else at
ingest, keeping the relay lean and spam-resistant. Read-side behaviour is
untouched — this only governs what gets written. The policy applies to every
ingest path, including events pulled in via negentropy sync (sourceType=Sync).

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


def decide(req):
    """Map one plugin request to an accept/reject reply. Fails closed on any
    structurally unexpected input rather than trusting it."""
    event = req.get("event")
    if not isinstance(event, dict):
        return {"id": "", "action": "reject", "msg": "bad event structure"}
    event_id = event.get("id")
    if not isinstance(event_id, str):
        event_id = ""
    # Apply the allowlist to every request type. strfry currently only sends
    # type "new" (incl. for sync ingest), but checking unconditionally means a
    # future type can never slip an unwanted kind past the policy.
    if event.get("kind") not in ALLOWED_KINDS:
        return {
            "id": event_id,
            "action": "reject",
            "msg": "blocked: event kind not accepted by this relay",
        }
    return {"id": event_id, "action": "accept", "msg": ""}


def main():
    # Use readline() in a loop rather than `for line in sys.stdin`: the protocol
    # is synchronous (strfry blocks waiting for each reply), so we must never let
    # Python's iterator read-ahead buffer stall the exchange. We flush after
    # every reply so strfry always sees it promptly.
    while True:
        line = sys.stdin.readline()
        if not line:
            break  # strfry closed stdin (shutdown/restart) — exit cleanly.
        line = line.strip()
        if not line:
            continue
        try:
            reply = decide(json.loads(line))
        except Exception as e:
            # A malformed request must never crash the loop and take the relay's
            # write path down with it. Fail closed and log for the operator.
            sys.stderr.write("strfry-writepolicy: %s\n" % e)
            sys.stderr.flush()
            reply = {"id": "", "action": "reject", "msg": "policy error"}
        sys.stdout.write(json.dumps(reply) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
