# Controller operations

## Role and build

The executable entry is `cmd/xdrop-controller`, with implementation under `core/` and console source at `../console/`. From the repository root run `./scripts/build-controller.sh all`: web builds the console, go builds with `-tags webui -trimpath`, and all performs them in order. The go step refuses a missing `core/webui/build/index.html`; a build without the tag embeds only the placeholder page.

`XDROP_SKIP_NPM_CI=1` explicitly uses existing frontend dependencies; the default runs `npm ci`. In `controller/`, `make all` builds web then Go; `make web`, `make build`, `make run CONFIG=/absolute/path/controller.example.yaml`, `make test`, `make clean` and `make dev CONFIG=...` are available. `make deps` downloads Go modules and installs console dependencies; neither build path runs `go mod tidy`.

## Configuration

| Key | Required value |
|---|---|
| `listen` | Host and port; port 1..65535; example `127.0.0.1:8000` |
| `database` | Absolute SQLite file path |
| `secret_key_file` | Absolute master-key file path |

There are no defaults. Unknown fields, duplicate keys and multiple YAML documents are rejected. `nodes` is rejected because nodes are stored in the database; `reconcile_interval` is rejected because the interval is a setting. Keep the listener on loopback behind a same-host HTTPS reverse proxy for browser sessions.

The key file must have mode 0600 and contain a base64-encoded 32-byte key. Node API keys are encrypted with AES-256-GCM and the node name as authenticated data; missing or invalid master material prevents startup. Individual unreadable stored node keys remain visible with `key_unreadable` and send no node requests.

## Initialization and CLI

Put `-config <absolute-file>` before the subcommand. Initialize the master key, then add the administrator; [Getting started](../GETTING_STARTED.md) provides complete commands.

| Command after `-config <file>` | Behavior |
|---|---|
| `secret-key init` | Create 0600 master file; refuse overwrite; no database open |
| `user add <name>` | Read password; create admin |
| `user passwd <name>` | Reset password and revoke sessions |
| `node add <name> --url <url> --key-stdin` | Register node using one key line from stdin |
| `node update <name> [--url <url>] [--key-stdin]` | Change URL and/or key |
| `node delete <name>` | Remove stored node |

Terminal passwords are entered twice without echo; piped input is one line. Passwords must be 10..72 bytes. CLI success returns 0, operation errors 1, invalid command syntax 2. Node writes through this CLI are for a stopped controller: use UI/API changes while running, because the CLI does not refresh its in-memory clients.

## Process management

From the repository root, use `scripts/manage-controller.sh start|stop|restart|status|logs`. Set absolute `XDROP_CONFIG` and `XDROP_RUN_DIR` to override `controller/config.yaml` and `controller/run`. Runtime files are `service.pid`, `service.exit`, `service.log`; management operations use `manager.lock`.

The script records the binary PID and verifies its exact binary/config command before signaling it. `stop` sends SIGTERM, waits up to 30 seconds and never escalates to SIGKILL; the controller drains HTTP with a 10-second deadline, closes event streams, stops workers and closes storage. `status` returns 0 for running, 3 for stopped. `logs` follows the log. If identity or lock validation fails, inspect the recorded process before manually repairing runtime files. Initialization is never part of start.

## Authentication and daily operations

Users log in with server-side sessions; the ticket is opaque, not JWT. Machines use named API credentials with `Authorization: Bearer <machine-key>`. Do not combine a session cookie and machine header. Administrator routes require an admin user session; operator sessions can manage rules and read operational data within the [API route table](API.md).

Register or test nodes in Nodes/settings, edit rules and whitelist, and inspect per-rule delivery, capacity, traffic history and audit. Node keys are write-only API input, never list/detail output. For rotation, change the node configuration and restart that node, then PATCH its controller registration with the matching key; the API replaces that client without restarting the controller. Expect temporary authentication failure between the two changes.

Reconciliation defaults to 15 minutes through `reconcile_interval_minutes`, range 1..1440. It runs only on eligible online, compatible, non-overloaded nodes and sides with no pending full/dirty work; persistent drift is exposed instead of promising unconditional repair.

## Upgrade and recovery

Stop the controller before taking a file copy of its database and master key; retain the matching executable and configuration. Startup opens/migrates storage and prepares stored rules. There is no downgrade command: rollback means restoring a compatible saved executable, database and master-key set after stopping.

The current node client accepts synchronization protocol 11. Upgrade compatible components together; a mismatched node is incompatible and is not synchronized. Node restart clears policy until full rules and whitelist snapshots recover; check each node before proceeding to the next.

If the master key is lost, point `secret_key_file` to a new path, initialize it and restart; then supply each node API key again through PATCH. This repairs unreadable rows but cannot recover old key plaintext. No automatic master-key regeneration or rotation is provided.
