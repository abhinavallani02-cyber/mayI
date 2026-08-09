# mayI

mayI is a proxy that sits between an MCP client (an AI agent) and an MCP
server (a set of tools), enforcing a policy on every `tools/call` request
before it reaches the server. For each call it decides `allow`, `deny`, or
`ask` — and `ask` pauses to prompt a human at the terminal before letting
the call through. Everything else (initialization, tool listing, responses,
notifications) passes through unmodified. The goal is that a human can put
real limits on what an agent is allowed to do without needing to trust the
agent, or the server, to enforce them itself.

## Status

Early and small. It has only been tested against one server
(`@modelcontextprotocol/server-filesystem`) over stdio, which is currently
the only transport it supports — no HTTP or SSE. Policy matching is tool
name (with glob support) plus an optional path-prefix check on arguments;
there's no general condition language yet. It has not had a security
review. Treat it as a working prototype, not a hardened boundary.

## Usage

```
node mayi.mjs [--policy <file>] [--audit <file>] [--audit-include-args] -- <command> [args...]
```

Everything after `--` is the real MCP server to spawn and front. For
example, to guard the filesystem server:

```
node mayi.mjs --policy policy.yaml --audit audit.jsonl -- \
  node node_modules/@modelcontextprotocol/server-filesystem/dist/index.js /path/to/allow
```

Point your MCP client at `mayi.mjs` (with its arguments) instead of at the
real server directly — mayI spawns the real server itself and speaks the
same stdio protocol on its own stdin/stdout, so from the client's
perspective nothing else changes.

Flags:

- `--policy <file>` — path to the policy YAML file. Defaults to
  `policy.yaml` in the current directory.
- `--audit <file>` — path to the audit log. Defaults to `audit.jsonl`.
- `--audit-include-args` — include each call's arguments in the audit log.
  Off by default; see [Audit logging](#audit-logging).

## Policy

A policy file is a list of rules, checked in order — the first matching
rule wins. Each rule matches on the tool name (supporting `*` as a glob)
and, optionally, a `path_prefix` checked against the call's `path`,
`source`, or `destination` argument, whichever is present.

```yaml
rules:
  - tool: read_*
    action: allow

  - tool: write_file
    path_prefix: /etc
    action: deny

  - tool: write_*
    action: ask

  - tool: "*"
    action: allow
```

The three actions:

- **`allow`** — the call is forwarded to the server immediately, no
  logging beyond the normal verdict line.
- **`deny`** — the call never reaches the server. mayI sends a JSON-RPC
  error back to the client on the same request id instead.
- **`ask`** — mayI prints the tool name and arguments to the terminal and
  waits (up to 30 seconds) for a human to type `y` or `n`. `y` forwards
  the call as if it were `allow`; `n`, any other answer, or a timeout
  denies it as if it were `deny`. If there's no controlling terminal to
  ask (e.g. mayI's own input/output are both piped, with no tty attached),
  `ask` always resolves to deny — there's no human to ask, so the safe
  default applies.

If no rule matches a call, mayI defaults to `ask` rather than silently
allowing it.

## Audit logging

Every verdict — `allow`, `deny`, `ask` → approved, or `ask` → denied — is
appended to the audit log as one JSON object per line:

```json
{"timestamp":"2026-08-09T03:21:42.139Z","id":3,"tool":"write_file","verdict":"ask→approved"}
```

By default the log records only the decision: timestamp, request id, tool
name, and verdict. It does **not** include the call's arguments — file
paths, file contents, or anything else passed to the tool — because
arguments can carry sensitive data that shouldn't end up in a plaintext
log file just from running the proxy. Pass `--audit-include-args` to
include them anyway, if you want a more detailed log and understand what
that means for the log file's contents.

Response payloads (what the server actually returned) are never written
to the audit log, in either mode.
