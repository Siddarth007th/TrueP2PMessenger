const express=require('express'),app=express(),http=require('http').createServer(app),io=require('socket.io')(http);
const net=require('net'),crypto=require('crypto'),Database=require('better-sqlite3');
const { startAnomalyDetector } = require('./anomaly-detector');
const { wrapOnion, peelOnion, wrapReturnOnion } = require('./onion-router');
const { rehydrate, rehydrateLocker } = require('./rehydrator');

const [,,nm,uiP,tcpP,...pp]=process.argv;
const ecdh=crypto.createECDH('secp256k1');ecdh.generateKeys();const myPk=ecdh.getPublicKey('hex');
const db=new Database(__dirname+`/node-${nm}.db`);
db.exec(`CREATE TABLE IF NOT EXISTS vault(id INTEGER PRIMARY KEY AUTOINCREMENT,msgId TEXT UNIQUE,fromNode TEXT,toNode TEXT,nonce TEXT,tag TEXT,val TEXT,ts INTEGER)`);
const keys={},socks={},ready=new Set(),seen=new Set();

// --- Port map: maps peer node names to their UI (HTTP) ports for onion routing ---
const peerPortMap = {};
// Known topology for the 4-node mesh (A, B, C, D):
const TOPOLOGY = { A: 3001, B: 3002, C: 3003, D: 3004 };

// --- Replication factor: doubles on each threat detection ---
let replicationFactor = 1;

const enc=(k,t)=>{const n=crypto.randomBytes(12),c=crypto.createCipheriv('aes-256-gcm',k,n),v=c.update(t,'utf8','hex')+c.final('hex');return{nonce:n.toString('hex'),tag:c.getAuthTag().toString('hex'),val:v};};
const dec=(k,n,t,v)=>{try{const c=crypto.createDecipheriv('aes-256-gcm',k,Buffer.from(n,'hex'));c.setAuthTag(Buffer.from(t,'hex'));return c.update(v,'hex','utf8')+c.final('utf8');}catch{return null;}};
const vr=()=>db.prepare('SELECT * FROM vault ORDER BY ts DESC LIMIT 100').all();
const emitServer=()=>{
const all=vr();
const mw=all.filter(r=>r.fromNode===nm||r.toNode===nm).map(r=>{const peer=r.fromNode===nm?r.toNode:r.fromNode;let pt='[awaiting key]';if(keys[peer])pt=dec(keys[peer],r.nonce,r.tag,r.val)||'[decrypt error]';return{...r,plaintext:pt};});
const lk=all.filter(r=>r.fromNode!==nm&&r.toNode!==nm);
io.emit('mywork',mw);
io.emit('locker',lk);
io.emit('REPLICATION_STATUS', { factor: replicationFactor, node: nm });
};

// --- Anomaly detector reference (set after http.listen) ---
let detector = null;

const store=m=>{
  try{
    db.prepare('INSERT OR IGNORE INTO vault(msgId,fromNode,toNode,nonce,tag,val,ts) VALUES(?,?,?,?,?,?,?)').run(m.id,m.from,m.to,m.nonce,m.tag,m.val,Date.now());
    if(detector){
      // Track in the correct set based on whether this node is party to the message
      if(m.from===nm||m.to===nm){
        detector.track(m.id);
      } else {
        detector.trackLocker(m.id);
      }
    }
  }catch{}
  emitServer();
};
const bcast=o=>{for(const p in socks){const arr=socks[p];if(arr.length>0)try{arr[0].write(JSON.stringify(o)+'\n');}catch{}}};
const handle=s=>{
s.write(JSON.stringify({t:'hello',n:nm,pk:myPk})+'\n');
let buf='';
s.on('data',d=>{buf+=d.toString();const ls=buf.split('\n');buf=ls.pop();ls.forEach(l=>{try{const m=JSON.parse(l);
if(m.t==='hello'&&m.n!==nm){if(!keys[m.n]){keys[m.n]=crypto.createHash('sha256').update(ecdh.computeSecret(Buffer.from(m.pk,'hex'))).digest();ready.add(m.n);peerPortMap[m.n]=TOPOLOGY[m.n];io.emit('peer-ready',m.n);io.emit('sys',`ECDH secp256k1 handshake with Node ${m.n} → AES-256-GCM key derived`);if(ready.size>=pp.length)io.emit('mesh-ready');}if(!socks[m.n])socks[m.n]=[];if(!socks[m.n].includes(s))socks[m.n].push(s);}
if(m.t==='msg'&&!seen.has(m.id)){seen.add(m.id);store(m);if(m.to===nm&&keys[m.from]){const txt=dec(keys[m.from],m.nonce,m.tag,m.val);if(txt)io.emit('chat-msg',{from:m.from,text:txt,group:!!m.group,msgId:m.id});}}
}catch{}});});
s.on('close',()=>{for(const p in socks)socks[p]=socks[p].filter(x=>x!==s);});
s.on('error',()=>{});
};
const tryConn=port=>{const s=net.connect(parseInt(port),'127.0.0.1');s.on('connect',()=>handle(s));s.on('error',()=>setTimeout(()=>tryConn(port),500));};
net.createServer(s=>handle(s)).listen(parseInt(tcpP),()=>{pp.forEach(p=>setTimeout(()=>tryConn(p),300));});

// ==========================================
// ONION-ROUTED RECOVERY — Express Routes
// ==========================================
app.use(express.json({ limit: '5mb' }));
app.use(express.static(__dirname+'/public'));

/**
 * POST /api/relay — Onion Routing Relay Endpoint
 *
 * Accepts an encrypted payload, peels one layer of AES-256-GCM encryption,
 * and either forwards to the next hop or processes the final payload.
 */
app.post('/api/relay', async (req, res) => {
  const { encryptedPayload } = req.body;

  if (!encryptedPayload || !encryptedPayload.nonce || !encryptedPayload.tag || !encryptedPayload.val) {
    return res.status(400).json({ error: 'Invalid onion payload' });
  }

  // Try each known AES key to peel the outer layer
  let peeled = null;
  let peeledPeer = null;

  for (const [peer, key] of Object.entries(keys)) {
    peeled = peelOnion(encryptedPayload, key);
    if (peeled) {
      peeledPeer = peer;
      break;
    }
  }

  if (!peeled) {
    console.log(`[Relay] Node ${nm}: could not decrypt onion layer — no matching key`);
    return res.status(403).json({ error: 'Cannot decrypt layer' });
  }

  io.emit('ONION_HOP', {
    node: nm,
    from: peeledPeer,
    hasNext: peeled.next !== null,
    timestamp: Date.now(),
  });

  console.log(`[Relay] Node ${nm}: peeled layer from ${peeledPeer}, next=${peeled.next || 'FINAL'}`);

  if (peeled.next !== null) {
    // Intermediate hop: forward the inner blob to the next relay
    try {
      const resp = await fetch(`${peeled.next}/api/relay`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ encryptedPayload: peeled.inner }),
      });
      const data = await resp.json();
      return res.json(data);
    } catch (err) {
      console.error(`[Relay] Forward to ${peeled.next} failed:`, err.message);
      return res.status(502).json({ error: 'Relay forward failed' });
    }
  }

  // Final destination: process the inner payload
  const payload = peeled.inner;

  if (payload && payload.type === 'RECOVERY_REQUEST') {
    // This node is being asked to supply rows from its vault
    console.log(`[Relay] Node ${nm}: RECOVERY_REQUEST for ${payload.missingIds.length} msgId(s)`);

    const found = [];
    const selectStmt = db.prepare('SELECT * FROM vault WHERE msgId = ?');

    for (const msgId of payload.missingIds) {
      const row = selectStmt.get(msgId);
      if (row) {
        found.push({
          msgId: row.msgId,
          fromNode: row.fromNode,
          toNode: row.toNode,
          nonce: row.nonce,
          tag: row.tag,
          val: row.val,
          ts: row.ts,
        });
      }
    }

    console.log(`[Relay] Node ${nm}: found ${found.length}/${payload.missingIds.length} requested rows`);

    // Build a return onion to send the data back to the origin
    if (payload.returnPath && payload.returnPath.length > 0 && found.length > 0) {
      const returnHops = payload.returnPath.map(rp => ({
        key: keys[rp.node],
        nextAddr: `http://localhost:${TOPOLOGY[rp.node]}`,
      })).filter(h => h.key);

      if (returnHops.length > 0) {
        const responsePayload = {
          type: 'RECOVERY_RESPONSE',
          rows: found,
          originNode: payload.originNode,
          recoveryType: payload.recoveryType || 'mywork',
        };

        const returnOnion = wrapReturnOnion(responsePayload, returnHops);

        try {
          await fetch(`${returnOnion.firstHop}/api/relay`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ encryptedPayload: returnOnion.ciphertext }),
          });
          console.log(`[Relay] Node ${nm}: return onion dispatched via ${returnOnion.firstHop}`);
        } catch (err) {
          console.error(`[Relay] Return onion dispatch failed:`, err.message);
        }
      }

      return res.json({ status: 'recovery_dispatched', found: found.length });
    }

    // If no return path, respond directly (fallback for simple topology)
    return res.json({ status: 'found', rows: found });
  }

  if (payload && payload.type === 'RECOVERY_RESPONSE') {
    // We're the origin and the data has come back
    console.log(`[Relay] Node ${nm}: RECOVERY_RESPONSE arrived with ${payload.rows.length} row(s) [type: ${payload.recoveryType || 'mywork'}]`);

    if (payload.recoveryType === 'locker') {
      rehydrateLocker(db, nm, payload.rows, io, detector);
    } else {
      rehydrate(db, nm, keys, payload.rows, io, detector);
    }
    emitServer();

    return res.json({ status: 'rehydrated', count: payload.rows.length });
  }

  if (payload && payload.type === 'REPLICATE_VAULT') {
    // Another node is asking us to store extra copies of data in our locker
    console.log(`[Relay] Node ${nm}: REPLICATE_VAULT — ${payload.rows.length} row(s) from ${payload.originNode}`);

    const insertStmt2 = db.prepare(
      'INSERT OR IGNORE INTO vault(msgId, fromNode, toNode, nonce, tag, val, ts) VALUES(?, ?, ?, ?, ?, ?, ?)'
    );

    let stored = 0;
    for (const row of payload.rows) {
      try {
        const result = insertStmt2.run(
          row.msgId, row.fromNode, row.toNode,
          row.nonce, row.tag, row.val,
          row.ts || Date.now()
        );
        if (result.changes > 0) {
          stored++;
          if (detector) {
            // Track as appropriate
            if (row.fromNode === nm || row.toNode === nm) {
              detector.track(row.msgId);
            } else {
              detector.trackLocker(row.msgId);
            }
          }
        }
      } catch {}
    }

    console.log(`[Relay] Node ${nm}: replicated ${stored}/${payload.rows.length} rows into vault`);

    io.emit('REPLICATION_RECEIVED', {
      from: payload.originNode,
      stored,
      total: payload.rows.length,
      timestamp: Date.now(),
    });
    io.emit('sys', `📡 Received ${stored} replicated vault record(s) from Node ${payload.originNode}`);
    emitServer();

    return res.json({ status: 'replicated', stored });
  }

  return res.json({ status: 'processed' });
});

/**
 * Initiate an onion-routed recovery for a set of missing msgIds.
 *
 * Builds onion circuits through available peers, wraps the
 * recovery request, and POSTs to the first hop.
 *
 * @param {string[]} missingIds - Array of missing msgIds
 * @param {string}   recoveryType - 'mywork' or 'locker'
 */
async function initiateRecovery(missingIds, recoveryType = 'mywork') {
  const peers = Object.keys(keys);

  if (peers.length < 1) {
    console.log(`[Recovery] Node ${nm}: no peers available for recovery`);
    io.emit('sys', '❌ Recovery failed: no peers connected');
    return;
  }

  console.log(`[Recovery] Node ${nm}: initiating onion-routed ${recoveryType} recovery for ${missingIds.length} msgId(s)`);
  io.emit('sys', `🧅 Initiating onion-routed ${recoveryType} recovery for ${missingIds.length} record(s)...`);

  for (let targetIdx = 0; targetIdx < peers.length; targetIdx++) {
    const target = peers[targetIdx];
    const intermediates = peers.filter(p => p !== target);

    // Build the hop list: intermediates first, target last
    const hopList = [];
    for (const mid of intermediates) {
      hopList.push({
        key: keys[mid],
        nextAddr: `http://localhost:${TOPOLOGY[mid]}`,
        node: mid,
      });
    }
    hopList.push({
      key: keys[target],
      nextAddr: `http://localhost:${TOPOLOGY[target]}`,
      node: target,
    });

    // Build return path: target → intermediates (reverse) → origin
    const returnPath = [];
    for (let i = intermediates.length - 1; i >= 0; i--) {
      returnPath.push({ node: intermediates[i] });
    }
    returnPath.push({ node: nm });

    const payload = {
      type: 'RECOVERY_REQUEST',
      missingIds,
      originNode: nm,
      originAddr: `http://localhost:${TOPOLOGY[nm]}`,
      returnPath,
      recoveryType,
    };

    // Trim to max 3 hops
    const hops = hopList.slice(0, 3);

    try {
      const onion = wrapOnion(payload, hops);

      io.emit('ONION_HOP', {
        node: nm,
        action: 'WRAP',
        layers: hops.length,
        target,
        timestamp: Date.now(),
      });

      await fetch(`${onion.firstHop}/api/relay`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ encryptedPayload: onion.ciphertext }),
      });

      console.log(`[Recovery] Node ${nm}: onion dispatched to ${target} via ${hops.map(h => h.node).join('→')}`);
    } catch (err) {
      console.error(`[Recovery] Onion dispatch to ${target} failed:`, err.message);
    }
  }
}

/**
 * Exponential Vault Replication — Spread recovered data to peer lockers.
 *
 * After recovery, sends REPLICATE_VAULT payloads via onion routing
 * to all peers, asking them to store the data in their lockers.
 * The replication factor doubles on each threat.
 *
 * @param {Array} rows - The rows to replicate
 */
async function replicateVault(rows) {
  const peers = Object.keys(keys);
  if (peers.length < 1 || rows.length === 0) return;

  console.log(`[Replication] Node ${nm}: spreading ${rows.length} row(s) to ${peers.length} peers (factor: ${replicationFactor})`);
  io.emit('sys', `📡 Spreading ${rows.length} record(s) across ${peers.length} peer lockers (replication factor: ×${replicationFactor})`);

  // Send replication commands to each peer via onion routing
  for (const target of peers) {
    const intermediates = peers.filter(p => p !== target);

    const hopList = [];
    for (const mid of intermediates.slice(0, 2)) {
      hopList.push({
        key: keys[mid],
        nextAddr: `http://localhost:${TOPOLOGY[mid]}`,
        node: mid,
      });
    }
    hopList.push({
      key: keys[target],
      nextAddr: `http://localhost:${TOPOLOGY[target]}`,
      node: target,
    });

    const hops = hopList.slice(0, 3);

    const payload = {
      type: 'REPLICATE_VAULT',
      rows: rows.map(r => ({
        msgId: r.msgId, fromNode: r.fromNode, toNode: r.toNode,
        nonce: r.nonce, tag: r.tag, val: r.val, ts: r.ts,
      })),
      originNode: nm,
      replicationFactor,
    };

    try {
      const onion = wrapOnion(payload, hops);
      await fetch(`${onion.firstHop}/api/relay`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ encryptedPayload: onion.ciphertext }),
      });
      console.log(`[Replication] Node ${nm}: vault replicated to ${target} via ${hops.map(h => h.node).join('→')}`);
    } catch (err) {
      console.error(`[Replication] Dispatch to ${target} failed:`, err.message);
    }
  }

  io.emit('REPLICATION_SPREAD', {
    factor: replicationFactor,
    rows: rows.length,
    peers: peers.length,
    timestamp: Date.now(),
    node: nm,
  });
}

// ==========================================
// Socket.IO — Client Events
// ==========================================
io.on('connection',s=>{
s.emit('init',{name:nm});
emitServer();
ready.forEach(p=>s.emit('peer-ready',p));
if(ready.size>=pp.length)s.emit('mesh-ready');
s.on('send-dm',d=>{if(!keys[d.to])return;const e=enc(keys[d.to],d.text),id=crypto.randomUUID(),m={t:'msg',id,from:nm,to:d.to,nonce:e.nonce,tag:e.tag,val:e.val};store(m);bcast(m);s.emit('chat-msg',{from:'Me',text:d.text,to:d.to,msgId:id});});
s.on('send-group',d=>{let firstId; for(const p of Object.keys(keys)){const e=enc(keys[p],d.text),id=crypto.randomUUID(),m={t:'msg',id,from:nm,to:p,nonce:e.nonce,tag:e.tag,val:e.val,group:true}; if(!firstId) firstId=id; store(m);bcast(m);}s.emit('chat-msg',{from:'Me',text:d.text,group:true,msgId:firstId});});

// --- Onion Recovery: Manual triggers ---
s.on('simulate-wipe', () => {
  // --- SMART ATTACKER: Wipe both My Work AND Locker ---
  const myWorkRows = db.prepare(
    'SELECT msgId FROM vault WHERE fromNode = ? OR toNode = ? ORDER BY RANDOM() LIMIT 3'
  ).all(nm, nm);

  const lockerRows = db.prepare(
    'SELECT msgId FROM vault WHERE fromNode != ? AND toNode != ? ORDER BY RANDOM() LIMIT 3'
  ).all(nm, nm);

  const allWipeIds = [
    ...myWorkRows.map(r => r.msgId),
    ...lockerRows.map(r => r.msgId),
  ];

  if (allWipeIds.length === 0) {
    s.emit('sys', '⚠️ No records to wipe — send some messages first');
    return;
  }

  const delStmt = db.prepare('DELETE FROM vault WHERE msgId = ?');
  for (const id of allWipeIds) {
    delStmt.run(id);
  }

  const myCount = myWorkRows.length;
  const lkCount = lockerRows.length;

  console.log(`[Wipe] Node ${nm}: smart wipe — ${myCount} My Work + ${lkCount} Locker record(s)`);
  io.emit('sys', `🗑️ SMART WIPE: ${myCount} My Work + ${lkCount} Locker record(s) deleted without signature`);
  emitServer();
});

s.on('trigger-recovery', () => {
  io.emit('sys', '🔍 Manual recovery scan triggered...');
  const currentRows = db.prepare(
    'SELECT msgId FROM vault WHERE fromNode = ? OR toNode = ?'
  ).all(nm, nm);
  const currentIds = new Set(currentRows.map(r => r.msgId));

  const missing = [];
  for (const id of seen) {
    if (!currentIds.has(id)) {
      missing.push(id);
    }
  }

  if (missing.length > 0) {
    io.emit('sys', `🔍 Found ${missing.length} recoverable record(s) — initiating onion routing...`);
    initiateRecovery(missing, 'mywork');
  } else {
    io.emit('sys', '✅ All records intact — no recovery needed');
  }
});

});

http.listen(parseInt(uiP),()=>{
  console.log(`Node ${nm} UI: ${uiP} | TCP: ${tcpP}`);

  // Start the anomaly detector after the server is listening
  detector = startAnomalyDetector(db, nm, io,
    // My Work anomaly callback
    (missingIds) => {
      // Double the replication factor on each threat
      replicationFactor *= 2;
      io.emit('REPLICATION_STATUS', { factor: replicationFactor, node: nm });
      io.emit('sys', `⚡ Replication factor doubled to ×${replicationFactor}`);
      console.log(`[Threat] Node ${nm}: replication factor → ×${replicationFactor}`);

      initiateRecovery(missingIds, 'mywork').then(() => {
        // After recovery, spread data to peers
        setTimeout(() => {
          const allRows = db.prepare(
            'SELECT * FROM vault WHERE fromNode = ? OR toNode = ?'
          ).all(nm, nm);
          if (allRows.length > 0) {
            replicateVault(allRows);
          }
        }, 3000);
      });
    },
    // Locker anomaly callback
    (missingLockerIds) => {
      initiateRecovery(missingLockerIds, 'locker');
    }
  );
});
