#!/usr/bin/env node

/**
 * radar_live.js — Bi-Directional DarkEden Terminal Radar
 */

const { spawn, execSync } = require('child_process');
const readline = require('readline');
const path = require('path');

// ─── Config ────────────────────────────────────────────────────────────────

const CONFIG = {
  playerX: 0, 
  playerY: 0, 
  gridSize: 15,
  redrawMs: 100,
  filter: 'tcp port 9998', 
  host: '45.55.52.86',
};

const args = process.argv.slice(2);
const specifiedIface = (() => {
  const idx = args.indexOf('--interface');
  return idx !== -1 && args[idx + 1] ? args[idx + 1] : null;
})();
const DEBUG = args.includes('--debug');

if (args.includes('--list')) {
  const tsharkBin = findTshark();
  if (!tsharkBin) { console.error('tshark not found'); process.exit(1); }
  const out = execSync(`"${tsharkBin}" -D`, { encoding: 'utf8' });
  console.log(out.replace(/\r/g, ''));
  process.exit(0);
}

// ─── State ─────────────────────────────────────────────────────────────────

const entities = new Map();
let lastPacketTime = null;
let redrawPending = false;
let totalPackets = 0;
let tsharkProcess = null;

// ─── Outbound Opcode Histogram (debug tracking) ───────────────────────────

const outboundOpcodes = new Map();

// ─── Garbage Collection ────────────────────────────────────────────────────

function garbageCollectEntities() {
  const now = Date.now();
  const timeout = 10000;
  let removed = 0;
  for (const [id, ent] of entities) {
    if (now - ent.lastSeen > timeout) {
      entities.delete(id);
      removed++;
    }
  }
  if (removed > 0) scheduleRedraw();
}

// ─── Grid Builder ──────────────────────────────────────────────────────────

function buildGrid() {
  const size = CONFIG.gridSize;
  const center = Math.floor(size / 2);
  const grid = Array.from({ length: size }, () => Array(size).fill('.'));
  
  const isPlayerSynced = (CONFIG.playerX > 0 && CONFIG.playerY > 0);
  grid[center][center] = isPlayerSynced ? 'P' : '?';

  for (const [id, pos] of entities.entries()) {
    // Only run garbage collection if the player has established a valid coordinate
    if (isPlayerSynced) {
      const dx = pos.x - CONFIG.playerX;
      const dy = pos.y - CONFIG.playerY;
      
      if (Math.abs(dx) > 40 || Math.abs(dy) > 40) {
        entities.delete(id);
        continue;
      }
      
      const gx = center + dx;
      const gy = center + dy;
      if (gx >= 0 && gx < size && gy >= 0 && gy < size) {
        if (grid[gy][gx] === '.') grid[gy][gx] = pos.initial;
      }
    }
  }

  return grid;
}

// ─── Renderer ──────────────────────────────────────────────────────────────

function render() {
  const grid = buildGrid();
  const lines = [];

  lines.push('\x1b[H');
  lines.push('\x1b[37m┌─ RADAR ──────────────────────────────┐\x1b[0m');
  for (const row of grid) {
    const cells = row
      .map(c => {
        if (c === 'P') return '\x1b[36mP\x1b[0m';
        if (c === '?') return '\x1b[33m?\x1b[0m';
        if (c === 'M') return '\x1b[35mM\x1b[0m'; // Ghost entities
        if (c !== '.') return '\x1b[31m' + c + '\x1b[0m';
        return '\x1b[90m.\x1b[0m';
      })
      .join(' ');
    lines.push('\x1b[37m│\x1b[0m ' + cells + ' \x1b[37m│\x1b[0m');
  }
  lines.push('\x1b[37m└──────────────────────────────────────┘\x1b[0m');
  
  const coordStr = (CONFIG.playerX > 0 && CONFIG.playerY > 0) 
    ? `X: ${CONFIG.playerX}, Y: ${CONFIG.playerY}` 
    : "WALK TO SYNC COORDINATES";

  lines.push(
    ` \x1b[90mPos: ${coordStr}  |  ` +
    `Monsters: ${entities.size}  |  ` +
    `Total Packets: ${totalPackets}\x1b[0m`
  );
  if (DEBUG && outboundOpcodes.size > 0) {
    const parts = [];
    for (const [k, v] of outboundOpcodes) parts.push(`${k}:${v}`);
    lines.push(` \x1b[90mOutbound: ${parts.join(', ')}\x1b[0m`);
  }
  lines.push(' \x1b[90mCtrl+C to exit\x1b[0m');

  process.stdout.write(lines.join('\r\n') + '\r\n');
}

// ─── Parser ────────────────────────────────────────────────────────────────

function parseTcpPayload(payload, srcIp) {
  if (CONFIG.host !== srcIp && srcIp !== '127.0.0.1' && !srcIp.startsWith('192.168.')) {
    CONFIG.host = srcIp; 
  }

  const isFromServer = (srcIp === CONFIG.host);
  let i = 0;
  
  while (i + 6 <= payload.length) {
    const opcode = payload[i];
    const length = (payload[i+1] << 8) | payload[i+2];

    if (length < 0 || length > 10000 || i + 6 + length > payload.length) break; 

    // 1. OUTBOUND PLAYER MOVEMENT (0x0E) - Client to Server
    if (opcode === 0x0E && length >= 3 && !isFromServer) {
      const newX = payload[i + 7];
      const newY = payload[i + 8];
      
      if (newX !== 0 && newY !== 0) {
        CONFIG.playerX = newX;
        CONFIG.playerY = newY;
        lastPacketTime = new Date();
        if (DEBUG) process.stderr.write(`[SYNC] 0x0E: X=${newX}, Y=${newY}\n`);
      }
    }

    // 2. OUTBOUND PLAYER MOVEMENT (0x54 alt) - Client to Server
    else if (opcode === 0x54 && length >= 3 && !isFromServer) {
      const newX = payload[i + 7];
      const newY = payload[i + 8];
      
      if (newX !== 0 && newY !== 0) {
        CONFIG.playerX = newX;
        CONFIG.playerY = newY;
        lastPacketTime = new Date();
        if (DEBUG) process.stderr.write(`[SYNC] 0x54: X=${newX}, Y=${newY}\n`);
      }
    }

    // 2b. SERVER 0x54 (debug only — coordinate mapping unclear)
    else if (opcode === 0x54 && length >= 3 && isFromServer && DEBUG) {
      const x = payload[i + 7];
      const y = payload[i + 8];
      process.stderr.write(`[DBG] Server 0x54: X=${x}, Y=${y}\n`);
    }

    // 3. MONSTER SPAWN (0x2F) - Server to Client
    else if (opcode === 0x2F && length >= 14 && isFromServer) { 
      try {
        const entityId = payload.readUInt32LE(i + 6);
        const nameLen = payload[i + 12];
        
        if (i + 13 + nameLen + 5 < i + 6 + length) {
          let name = '';
          for (let n = 0; n < nameLen; n++) name += String.fromCharCode(payload[i + 13 + n]);
          
          const xOffset = i + 13 + nameLen + 4;
          const x = payload[xOffset];
          const y = payload[xOffset + 1];

          if (name.length > 0) {
            entities.set(entityId, { name, x, y, initial: name.charAt(0).toUpperCase(), lastSeen: Date.now() });
            lastPacketTime = new Date();
          }
        }
      } catch (_) {}
    }

    // 4. MONSTER MOVEMENT (0x52) - Server to Client
    else if (opcode === 0x52 && length >= 6 && isFromServer) { 
      try {
        const entityId = payload.readUInt32LE(i + 6);
        const x = payload[i + 10];
        const y = payload[i + 11];

        if (entities.has(entityId)) {
          const ent = entities.get(entityId);
          ent.x = x;
          ent.y = y;
          ent.lastSeen = Date.now();
        } else {
          // Ghost Registration: Catch pre-existing entities that move
          entities.set(entityId, { name: 'Unknown', x, y, initial: 'M', lastSeen: Date.now() });
        }
        lastPacketTime = new Date();
      } catch (_) {}
    }

    // 5. MONSTER DEATH / DESPAWN (0x45) - Server to Client
    else if (opcode === 0x45 && length >= 4 && isFromServer) {
      try {
        const entityId = payload.readUInt32LE(i + 6);
        if (entities.has(entityId)) {
          entities.delete(entityId);
          lastPacketTime = new Date();
        }
      } catch (_) {}
    }

    // 6. UNKNOWN OUTBOUND (debug tracking)
    else if (DEBUG && !isFromServer) {
      try {
        const key = `0x${opcode.toString(16).padStart(2, '0')}`;
        const count = (outboundOpcodes.get(key) || 0) + 1;
        outboundOpcodes.set(key, count);
        if (count <= 2) {
          const end = Math.min(i + 6 + length, i + 26);
          const hex = payload.slice(i, end).toString('hex').toUpperCase();
          process.stderr.write(`[???] Outbound ${key} (x${count}): ${hex}\n`);
        }
      } catch (_) {}
    }

    i += 6 + length;
  }
}

// ─── Core Execution ────────────────────────────────────────────────────────

function hexToBuffer(hexStr) {
  const clean = hexStr.replace(/[^0-9a-fA-F]/g, '');
  if (!clean || clean.length % 2 !== 0) return null;
  return Buffer.from(clean, 'hex');
}

function scheduleRedraw() {
  if (!redrawPending) {
    redrawPending = true;
    setTimeout(() => { redrawPending = false; render(); }, CONFIG.redrawMs);
  }
}

function processHexLine(line) {
  const parts = line.trim().split('\t');
  if (parts.length < 2) return;

  const srcIp = parts[0].trim();
  const hexData = parts[parts.length - 1].trim(); 
  const buf = hexToBuffer(hexData);
  
  if (!buf || buf.length === 0) return;

  totalPackets++;
  if (DEBUG) {
    const dir = (srcIp === CONFIG.host) ? '<<<' : '>>>';
    process.stderr.write(`[${dir}] ${hexData.slice(0, 80)}\n`);
  }
  const prevTime = lastPacketTime;
  
  parseTcpPayload(buf, srcIp);
  if (lastPacketTime !== prevTime) scheduleRedraw();
}

function findTshark() {
  const candidates = ['tshark'];
  if (process.platform === 'win32') {
    const programFiles = process.env['ProgramFiles'] || 'C:\\Program Files';
    candidates.push(path.join(programFiles, 'Wireshark', 'tshark.exe'));
  }
  for (const bin of candidates) {
    try { execSync(`"${bin}" --version`, { stdio: 'ignore' }); return bin; } 
    catch (_) { continue; }
  }
  return null;
}

function startTsharkCapture() {
  const tsharkBin = findTshark();
  if (!tsharkBin) process.exit(1);

  let iface = specifiedIface;
  if (!iface) {
    const out = execSync(`"${tsharkBin}" -D`, { encoding: 'utf8' });
    const lines = out.replace(/\r/g, '').trim().split('\n').filter(l => l.trim());
    const parsed = lines.map(l => {
      const m = l.match(/^(\d+)\.\s+(.+)/);
      return m ? { num: m[1], desc: m[2] } : null;
    }).filter(Boolean);

    const priority = ['wi-fi', 'wireless', 'wlan', 'ethernet'];
    let chosen = null;
    for (const term of priority) {
      chosen = parsed.find(p => p.desc.toLowerCase().includes(term));
      if (chosen) break;
    }
    if (!chosen) {
      chosen = parsed.find(p =>
        !p.desc.toLowerCase().includes('loopback') &&
        !p.desc.toLowerCase().includes('vmware') &&
        !p.desc.toLowerCase().includes('vethernet') &&
        !p.desc.toLowerCase().includes('bluetooth')
      );
    }
    iface = chosen ? chosen.num : (parsed[0] ? parsed[0].num : null);
  }

  render();
  setInterval(garbageCollectEntities, 5000);

  tsharkProcess = spawn(tsharkBin, [
    '-i', iface,
    '-f', CONFIG.filter,
    '-T', 'fields',
    '-e', 'ip.src',
    '-e', 'tcp.payload',
    '-l',
  ], { stdio: ['ignore', 'pipe', 'ignore'], windowsHide: true });

  readline.createInterface({ input: tsharkProcess.stdout }).on('line', processHexLine);
}

process.stdout.write('\x1b[?25l\x1b[2J');
startTsharkCapture();

process.on('SIGINT', () => {
  if (tsharkProcess) tsharkProcess.kill();
  process.stdout.write('\x1b[?25h\x1b[0m\n\nRadar stopped.\n');
  process.exit(0);
});