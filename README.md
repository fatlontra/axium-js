# Axium

A hybrid bot/radar system for DarkEden MMORPG.

## Architecture

| Layer | Language | Role |
|---|---|---|
| **Network Layer** | Node.js | Sniffs TCP packets (port 9998) to maintain a live on-screen monster list |
| **Logic Layer** | Python | Memory reading, map parsing, A* pathfinding, movement execution (planned) |

## Network Layer (Node.js)

Passive packet capture via `tshark` (Wireshark CLI). Parses DarkEden binary protocol opcodes:

- `0x0E` / `0x54` — Player movement/position sync
- `0x2F` — Monster spawn
- `0x52` — Monster movement
- `0x45` — Monster death/despawn
- `0x38` — Server position sync

### Radar Modes

**Live List** (`radar_live.js`) — Numbered list of on-screen monsters; auto-removes after 10s of no packets.

**List Radar** (`radar_parser_terminal.tsx`) — Boxed numbered list of all detected monsters.

### Usage

```bash
node radar_live.js                          # auto-detect network interface
node radar_live.js --interface 6            # specify interface number
node radar_live.js --debug                  # verbose packet logging

node radar_parser_terminal.tsx              # list-based radar
node radar_parser_terminal.tsx --list       # show available interfaces
```

### Requirements

- [Wireshark](https://www.wireshark.org/) (tshark CLI) installed and accessible
- Node.js
- `npm install` to install dependencies (`koffi` for future Windows API FFI)

## Logic Layer (Python) — Planned

- Memory reading via `pymem` (player coordinates from `DarkEden.exe`)
- Map/binary `.map` file parsing into 2D collision grids
- A* pathfinding with dynamic monster obstacles from the Node.js IPC stream
- Movement execution via simulated clicks or memory writes

See `AGENTS.md` for full specification.
