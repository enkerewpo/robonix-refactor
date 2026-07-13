# Keystone - user identity and access

Keystone is the Robonix system component that owns user identity, user
preferences, voiceprint bindings, and access decisions used by Liaison and
Pilot.

## Current implementation

The `robonix-keystone` crate provides the first in-memory core:

- create, list, and delete users;
- store JSON preferences per user;
- bind a voiceprint ID to one user;
- store per-user text and voice access settings;
- authorize text input under the global security configuration.

The core is intentionally independent of transport. Atlas registration, gRPC
contracts, persistent storage, and calls to the voiceprint service are the next
integration steps. Until those are connected, this crate is not a replacement
for Liaison's existing runtime access gate.

Run the focused tests from the repository root:

```bash
cargo test -p robonix-keystone
```
