/* Browser stand-ins for the few Node built-ins the VibeGuard engine uses.
 * Everything lives in memory: uploaded projects never leave the visitor's browser. */
(function (g) {
  'use strict';
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  // ---------------- Buffer (subset) ----------------
  class Buffer extends Uint8Array {
    static from(v, encoding) {
      if (typeof v === 'string') {
        if (encoding === 'base64' || encoding === 'base64url') {
          let s = v.replace(/-/g, '+').replace(/_/g, '/').replace(/[^A-Za-z0-9+/]/g, '');
          while (s.length % 4) s += '=';
          let bin;
          try { bin = atob(s); } catch { bin = ''; }
          const b = new Buffer(bin.length);
          for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i);
          return b;
        }
        if (encoding === 'hex') {
          const b = new Buffer(v.length >> 1);
          for (let i = 0; i < b.length; i++) b[i] = parseInt(v.substr(i * 2, 2), 16);
          return b;
        }
        const u = enc.encode(v);
        return new Buffer(u.buffer, u.byteOffset, u.byteLength);
      }
      if (v instanceof ArrayBuffer) return new Buffer(v);
      const b = new Buffer(v.length);
      b.set(v);
      return b;
    }
    static alloc(n, fill) { const b = new Buffer(n); if (typeof fill === 'number') b.fill(fill); return b; }
    static isBuffer(x) { return x instanceof Buffer; }
    static byteLength(s) { return typeof s === 'string' ? enc.encode(s).length : s.length; }
    static concat(list) {
      const total = list.reduce((n, b) => n + b.length, 0);
      const out = new Buffer(total);
      let o = 0;
      for (const b of list) { out.set(b, o); o += b.length; }
      return out;
    }
    toString(encoding = 'utf8', start = 0, end = this.length) {
      const v = this.subarray(start, end);
      if (encoding === 'hex') return Array.from(v, (x) => x.toString(16).padStart(2, '0')).join('');
      if (encoding === 'base64') { let s = ''; for (const x of v) s += String.fromCharCode(x); return btoa(s); }
      return dec.decode(v);
    }
    slice(a, b) { return this.subarray(a, b); }
    readUInt16LE(o) { return this[o] | (this[o + 1] << 8); }
    readUInt32LE(o) { return (this[o] | (this[o + 1] << 8) | (this[o + 2] << 16)) + this[o + 3] * 0x1000000; }
    writeUInt16LE(v, o) { this[o] = v & 255; this[o + 1] = (v >>> 8) & 255; return o + 2; }
    writeUInt32LE(v, o) { this[o] = v & 255; this[o + 1] = (v >>> 8) & 255; this[o + 2] = (v >>> 16) & 255; this[o + 3] = (v >>> 24) & 255; return o + 4; }
  }

  // ---------------- path (posix) ----------------
  function normalizeArray(parts, allowAbove) {
    const out = [];
    for (const p of parts) {
      if (!p || p === '.') continue;
      if (p === '..') { if (out.length && out[out.length - 1] !== '..') out.pop(); else if (allowAbove) out.push('..'); }
      else out.push(p);
    }
    return out;
  }
  const path = {
    sep: '/',
    delimiter: ':',
    isAbsolute: (p) => p.startsWith('/'),
    normalize(p) {
      if (p === '') return '.';
      const abs = p.startsWith('/');
      const trail = p.endsWith('/');
      let r = normalizeArray(p.split('/'), !abs).join('/');
      if (!r && !abs) r = '.';
      if (r && trail) r += '/';
      return (abs ? '/' : '') + r;
    },
    join(...parts) { const j = parts.filter((x) => x !== '').join('/'); return j ? path.normalize(j) : '.'; },
    resolve(...parts) {
      let r = '';
      for (let i = parts.length - 1; i >= 0 && !r.startsWith('/'); i--) if (parts[i]) r = parts[i] + (r ? '/' + r : '');
      if (!r.startsWith('/')) r = '/' + r;
      const n = '/' + normalizeArray(r.split('/'), false).join('/');
      return n;
    },
    dirname(p) {
      if (!p) return '.';
      const s = p.replace(/\/+$/, '');
      const i = s.lastIndexOf('/');
      if (i === -1) return '.';
      if (i === 0) return '/';
      return s.slice(0, i);
    },
    basename(p, ext) {
      let b = p.replace(/\/+$/, '');
      b = b.slice(b.lastIndexOf('/') + 1);
      if (ext && b.endsWith(ext) && b !== ext) b = b.slice(0, -ext.length);
      return b;
    },
    extname(p) {
      const b = path.basename(p);
      const i = b.lastIndexOf('.');
      return i <= 0 ? '' : b.slice(i);
    },
    relative(from, to) {
      const a = path.resolve(from).split('/').filter(Boolean);
      const b = path.resolve(to).split('/').filter(Boolean);
      let i = 0;
      while (i < a.length && i < b.length && a[i] === b[i]) i++;
      return [...Array(a.length - i).fill('..'), ...b.slice(i)].join('/');
    },
  };
  path.posix = path;

  // ---------------- fs (in memory) ----------------
  const files = new Map(); // abs path -> Buffer
  const dirs = new Set(['/']);
  const R = (p) => path.resolve(String(p));
  const enoent = (p) => Object.assign(new Error(`ENOENT: no such file or directory, '${p}'`), { code: 'ENOENT' });
  function addDirs(p) { let d = p; while (d && !dirs.has(d)) { dirs.add(d); d = path.dirname(d); } }
  const fs = {
    existsSync: (p) => files.has(R(p)) || dirs.has(R(p)),
    mkdirSync(p) { addDirs(R(p)); },
    writeFileSync(p, data) { const a = R(p); addDirs(path.dirname(a)); files.set(a, typeof data === 'string' ? Buffer.from(data) : Buffer.from(data)); },
    readFileSync(p, encoding) {
      const a = R(p);
      if (!files.has(a)) throw enoent(a);
      const b = files.get(a);
      return typeof encoding === 'string' ? b.toString(encoding) : encoding && encoding.encoding ? b.toString(encoding.encoding) : b;
    },
    statSync(p) {
      const a = R(p);
      if (files.has(a)) { const size = files.get(a).length; return { size, mtimeMs: Date.now(), isFile: () => true, isDirectory: () => false, isSymbolicLink: () => false }; }
      if (dirs.has(a)) return { size: 0, mtimeMs: Date.now(), isFile: () => false, isDirectory: () => true, isSymbolicLink: () => false };
      throw enoent(a);
    },
    readdirSync(p, opts) {
      const a = R(p);
      if (!dirs.has(a)) throw enoent(a);
      const prefix = a === '/' ? '/' : a + '/';
      const names = new Map();
      for (const d of dirs) if (d !== a && d.startsWith(prefix) && !d.slice(prefix.length).includes('/')) names.set(d.slice(prefix.length), 'dir');
      for (const f of files.keys()) if (f.startsWith(prefix) && !f.slice(prefix.length).includes('/')) names.set(f.slice(prefix.length), 'file');
      const list = [...names.keys()].sort();
      if (opts && opts.withFileTypes) return list.map((name) => ({ name, isFile: () => names.get(name) === 'file', isDirectory: () => names.get(name) === 'dir', isSymbolicLink: () => false }));
      return list;
    },
    rmSync(p) {
      const a = R(p);
      const prefix = a + '/';
      files.delete(a); dirs.delete(a);
      for (const f of [...files.keys()]) if (f.startsWith(prefix)) files.delete(f);
      for (const d of [...dirs]) if (d.startsWith(prefix)) dirs.delete(d);
    },
    renameSync(from, to) {
      const a = R(from), b = R(to);
      if (!files.has(a)) throw enoent(a);
      addDirs(path.dirname(b));
      files.set(b, files.get(a));
      files.delete(a);
    },
    copyFileSync(from, to) { fs.writeFileSync(to, fs.readFileSync(from)); },
    mkdtempSync(prefix) { const d = prefix + Math.random().toString(36).slice(2, 10); addDirs(R(d)); return R(d); },
  };

  // ---------------- small ones ----------------
  const zlib = {
    // ZIPs are inflated asynchronously (DecompressionStream) before scanning, so this path is never used.
    inflateRawSync() { throw Object.assign(new Error('Synchronous inflate is not available in the browser.'), { userFacing: true }); },
    // Output ZIPs are stored uncompressed: returning the input makes the writer pick "stored".
    deflateRawSync(data) { return data; },
  };
  const child_process = {
    spawnSync() { return { status: null, stdout: '', stderr: '', error: new Error('git is not available in the browser') }; },
    spawn() { throw new Error('child processes are not available in the browser'); },
  };
  const os = { tmpdir: () => '/tmp', platform: () => 'browser' };
  const crypto = {
    randomBytes(n) { const b = new Buffer(n); g.crypto.getRandomValues(b); return b; },
  };
  const process = { env: {}, version: 'v22.0.0', platform: 'browser', cwd: () => '/' };

  g.Buffer = g.Buffer || Buffer;
  g.process = g.process || process;
  g.VG_SHIMS = { fs, path, zlib, child_process, os, crypto, _memfs: { files, dirs } };
})(typeof window !== 'undefined' ? window : globalThis);
