#!/usr/bin/env node

/**
 * radar_live.js — Live monster list from packet capture
 *
 * Captures TCP packets via tshark, parses game entity spawn/move/despawn
 * packets, and renders a live numbered list of on-screen monsters.
 * Monsters are removed after 10s of no packets (walked off screen or killed).
 *
 * Usage:
 * node radar_live.js                          # auto-detect interface
 * node radar_live.js --interface 6            # specify interface number
 * node radar_live.js --list                   # show available interfaces
 * node radar_live.js --interface 6 --debug    # verbose packet logging
 *
 * Requires:
 * - Wireshark (tshark) installed
 */

const { spawn, execSync } = require('child_process');
const readline = require('readline');
const path = require('path');

// ─── Config ────────────────────────────────────────────────────────────────

const CONFIG = {
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

// ─── Renderer ──────────────────────────────────────────────────────────────

const BOX_W = 40;

function render() {
  const lines = [];
  const count = entities.size;
  const title = ' MONSTERS' + (count > 0 ? ' (' + count + ')' : '') + ' ';
  const dashes = BOX_W - 2 - title.length;
  const left = Math.floor(dashes / 2);
  const right = dashes - left;

  lines.push('\x1b[2J\x1b[H');
  lines.push('\x1b[37m\u250c' + '\u2500'.repeat(left) + title + '\u2500'.repeat(right) + '\u2510\x1b[0m');

  if (count === 0) {
    const pad = BOX_W - 10;
    lines.push('\x1b[37m\u2502\x1b[0m  \x1b[90m(none)\x1b[0m' + ' '.repeat(pad) + '\x1b[37m\u2502\x1b[0m');
  } else {
    let idx = 1;
    for (const [, ent] of entities) {
      const prefix = ' ' + idx + '. ';
      const maxName = BOX_W - prefix.length - 4;
      const name = ent.name.length > maxName ? ent.name.slice(0, maxName - 1) + '\u2026' : ent.name;
      const pad = BOX_W - prefix.length - name.length - 2;
      lines.push('\x1b[37m\u2502\x1b[0m' + prefix + '\x1b[33m' + name + '\x1b[0m' + ' '.repeat(Math.max(pad, 0)) + '\x1b[37m\u2502\x1b[0m');
      idx++;
    }
  }

  lines.push('\x1b[37m\u2514' + '\u2500'.repeat(BOX_W - 2) + '\u2518\x1b[0m');

  lines.push(' \x1b[90mPackets: ' + totalPackets + '\x1b[0m');

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

    // 1. MONSTER SPAWN (0x2F) - Server to Client
    if (opcode === 0x2F && length >= 14 && isFromServer) { 
      try {
        const entityId = payload.readUInt32LE(i + 6);
        const nameLen = payload[i + 12];
        
        if (i + 13 + nameLen + 5 < i + 6 + length) {
          let name = '';
          for (let n = 0; n < nameLen; n++) name += String.fromCharCode(payload[i + 13 + n]);

          if (name.length > 0) {
            entities.set(entityId, { name, lastSeen: Date.now() });
            lastPacketTime = new Date();
          }
        }
      } catch (_) {}
    }

    // 2. MONSTER MOVEMENT (0x52) - Server to Client (heartbeat to keep entity alive)
    else if (opcode === 0x52 && length >= 6 && isFromServer) { 
      try {
        const entityId = payload.readUInt32LE(i + 6);

        if (entities.has(entityId)) {
          entities.get(entityId).lastSeen = Date.now();
        } else {
          entities.set(entityId, { name: 'Unknown', lastSeen: Date.now() });
        }
        lastPacketTime = new Date();
      } catch (_) {}
    }

    // 3. MONSTER DEATH / DESPAWN (0x45) - Server to Client
    else if (opcode === 0x45 && length >= 4 && isFromServer) {
      try {
        const entityId = payload.readUInt32LE(i + 6);
        if (entities.has(entityId)) {
          entities.delete(entityId);
          lastPacketTime = new Date();
        }
      } catch (_) {}
    }

    // 4. UNKNOWN OUTBOUND (debug tracking)
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