// FallTrust · web-of-trust attestations · signed vouches + transitive score
// MIT · AI-Native Solutions · sovereign, browser-native
// Requires: FallID instance (for signing), optional FallLink instance (for gossip)

const DB_NAME = 'falltrust';
const STORE = 'vouches';
const DB_VER = 1;

function openDB() {
  return new Promise((resolve, reject) => {
    const r = indexedDB.open(DB_NAME, DB_VER);
    r.onupgradeneeded = () => {
      const db = r.result;
      if (!db.objectStoreNames.contains(STORE)) {
        const s = db.createObjectStore(STORE, { keyPath: 'id' });
        s.createIndex('vouchee', 'vouchee', { unique: false });
        s.createIndex('target', 'target', { unique: false });
      }
    };
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

async function dbPut(v) {
  const db = await openDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).put(v);
    tx.oncomplete = () => res(v);
    tx.onerror = () => rej(tx.error);
  });
}

async function dbAll() {
  const db = await openDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(STORE, 'readonly');
    const r = tx.objectStore(STORE).getAll();
    r.onsuccess = () => res(r.result || []);
    r.onerror = () => rej(r.error);
  });
}

async function dbDelete(id) {
  const db = await openDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).delete(id);
    tx.oncomplete = () => res();
    tx.onerror = () => rej(tx.error);
  });
}

function vouchId(vouchee, target) {
  return `${vouchee}::${target}`;
}

async function sha256Hex(str) {
  const buf = new TextEncoder().encode(str);
  const h = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(h)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function canonical(v) {
  // deterministic string for signing / verifying
  return JSON.stringify({
    vouchee: v.vouchee,
    target: v.target,
    claim: v.claim,
    strength: v.strength,
    timestamp: v.timestamp,
    revoked: !!v.revoked
  });
}

export class FallTrust {
  constructor({ fallidInstance, falllinkInstance } = {}) {
    if (!fallidInstance) throw new Error('FallTrust: fallidInstance required');
    this.fid = fallidInstance;
    this.link = falllinkInstance || null;
    this._listeners = new Set();
    this._wireLink();
  }

  _wireLink() {
    if (!this.link || typeof this.link.on !== 'function') return;
    try {
      this.link.on('falltrust:vouch', async (msg) => {
        if (msg && msg.data) {
          await this.importVouches([msg.data]);
        }
      });
    } catch (e) { /* silent */ }
  }

  onChange(fn) { this._listeners.add(fn); return () => this._listeners.delete(fn); }
  _emit() { for (const fn of this._listeners) { try { fn(); } catch(e){} } }

  async _myDid() {
    if (typeof this.fid.getDid === 'function') return await this.fid.getDid();
    if (this.fid.did) return this.fid.did;
    throw new Error('FallTrust: cannot resolve local DID');
  }

  async _sign(payload) {
    if (typeof this.fid.sign === 'function') return await this.fid.sign(payload);
    throw new Error('FallTrust: fallid.sign() unavailable');
  }

  async _verify(vouchee, payload, signature) {
    if (typeof this.fid.verify === 'function') {
      try { return await this.fid.verify(vouchee, payload, signature); }
      catch (e) { return false; }
    }
    // if no verifier, accept (permissive mode)
    return true;
  }

  async vouch(targetDid, claim, strength = 1.0) {
    if (!targetDid || typeof targetDid !== 'string') throw new Error('targetDid required');
    const s = Math.max(0, Math.min(1, Number(strength) || 0));
    const vouchee = await this._myDid();
    if (vouchee === targetDid) throw new Error('cannot vouch for self');
    const v = {
      vouchee,
      target: targetDid,
      claim: String(claim || '').slice(0, 500),
      strength: s,
      timestamp: Date.now(),
      revoked: false
    };
    v.signature = await this._sign(canonical(v));
    v.id = vouchId(vouchee, targetDid);
    await dbPut(v);
    this._gossip(v);
    this._emit();
    return v;
  }

  async revoke(targetDid) {
    const vouchee = await this._myDid();
    const id = vouchId(vouchee, targetDid);
    const all = await dbAll();
    const existing = all.find(v => v.id === id);
    if (!existing) return null;
    const v = { ...existing, revoked: true, timestamp: Date.now() };
    v.signature = await this._sign(canonical(v));
    await dbPut(v);
    this._gossip(v);
    this._emit();
    return v;
  }

  _gossip(v) {
    if (!this.link) return;
    try {
      if (typeof this.link.broadcast === 'function') {
        this.link.broadcast('falltrust:vouch', v);
      } else if (typeof this.link.send === 'function') {
        this.link.send('falltrust:vouch', v);
      } else if (typeof this.link.emit === 'function') {
        this.link.emit('falltrust:vouch', v);
      }
    } catch (e) { /* silent */ }
  }

  async listVouches() {
    const me = await this._myDid();
    const all = await dbAll();
    return all.filter(v => v.vouchee === me);
  }

  async listReceivedVouches() {
    const me = await this._myDid();
    const all = await dbAll();
    return all.filter(v => v.target === me && !v.revoked);
  }

  async neighbours(did) {
    const all = await dbAll();
    return all.filter(v => v.target === did && !v.revoked);
  }

  async _allActive() {
    const all = await dbAll();
    return all.filter(v => !v.revoked);
  }

  // BFS transitive trust: from local DID, expand outward.
  // score(target) = max over paths of product(strengths along path)
  // returns { score, path: [{vouchee, target, strength}] }
  async trustScore(targetDid, maxDepth = 3) {
    const me = await this._myDid();
    if (targetDid === me) return { score: 1, path: [] };
    const all = await this._allActive();

    // adjacency: vouchee -> [{ target, strength, edge }]
    const adj = new Map();
    for (const v of all) {
      if (!adj.has(v.vouchee)) adj.set(v.vouchee, []);
      adj.get(v.vouchee).push({ target: v.target, strength: v.strength, edge: v });
    }

    // Dijkstra-like on -log(strength) (shorter = higher score)
    const best = new Map(); // did -> { score, path }
    best.set(me, { score: 1, path: [] });
    const queue = [{ did: me, score: 1, path: [], depth: 0 }];

    while (queue.length) {
      // pop highest score
      queue.sort((a, b) => b.score - a.score);
      const cur = queue.shift();
      if (cur.depth >= maxDepth) continue;
      const edges = adj.get(cur.did) || [];
      for (const e of edges) {
        if (e.strength <= 0) continue;
        const nextScore = cur.score * e.strength;
        const nextPath = [...cur.path, { vouchee: cur.did, target: e.target, strength: e.strength, claim: e.edge.claim }];
        const prev = best.get(e.target);
        if (!prev || prev.score < nextScore) {
          best.set(e.target, { score: nextScore, path: nextPath });
          queue.push({ did: e.target, score: nextScore, path: nextPath, depth: cur.depth + 1 });
        }
      }
    }

    const r = best.get(targetDid);
    return r ? { score: Number(r.score.toFixed(6)), path: r.path } : { score: 0, path: [] };
  }

  async importVouches(peerVouches) {
    if (!Array.isArray(peerVouches)) peerVouches = [peerVouches];
    const all = await dbAll();
    const byId = new Map(all.map(v => [v.id, v]));
    let added = 0;
    for (const raw of peerVouches) {
      if (!raw || !raw.vouchee || !raw.target || !raw.signature) continue;
      const v = {
        vouchee: raw.vouchee,
        target: raw.target,
        claim: String(raw.claim || '').slice(0, 500),
        strength: Math.max(0, Math.min(1, Number(raw.strength) || 0)),
        timestamp: Number(raw.timestamp) || Date.now(),
        revoked: !!raw.revoked,
        signature: raw.signature
      };
      v.id = vouchId(v.vouchee, v.target);
      const ok = await this._verify(v.vouchee, canonical(v), v.signature);
      if (!ok) continue;
      const prev = byId.get(v.id);
      if (prev && prev.timestamp >= v.timestamp) continue;
      await dbPut(v);
      byId.set(v.id, v);
      added++;
    }
    if (added) this._emit();
    return { added, total: byId.size };
  }

  async graph() {
    const all = await this._allActive();
    const me = await this._myDid();
    const nodeSet = new Set([me]);
    const edges = [];
    for (const v of all) {
      nodeSet.add(v.vouchee);
      nodeSet.add(v.target);
      edges.push({ source: v.vouchee, target: v.target, strength: v.strength, claim: v.claim });
    }
    return { me, nodes: Array.from(nodeSet).map(id => ({ id })), edges };
  }

  async exportJSON() {
    const all = await dbAll();
    return JSON.stringify({ format: 'falltrust/v1', vouches: all }, null, 2);
  }

  async clearAll() {
    const all = await dbAll();
    for (const v of all) await dbDelete(v.id);
    this._emit();
  }
}

export default FallTrust;
