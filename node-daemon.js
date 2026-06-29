const express=require('express'),app=express(),http=require('http').createServer(app),io=require('socket.io')(http);
const net=require('net'),crypto=require('crypto'),Database=require('better-sqlite3');
const [,,nm,uiP,tcpP,...pp]=process.argv;
const ecdh=crypto.createECDH('secp256k1');ecdh.generateKeys();const myPk=ecdh.getPublicKey('hex');
const db=new Database(__dirname+`/node-${nm}.db`);
db.exec(`CREATE TABLE IF NOT EXISTS vault(id INTEGER PRIMARY KEY AUTOINCREMENT,msgId TEXT UNIQUE,fromNode TEXT,toNode TEXT,nonce TEXT,tag TEXT,val TEXT,ts INTEGER)`);
const keys={},socks={},ready=new Set(),seen=new Set();
const enc=(k,t)=>{const n=crypto.randomBytes(12),c=crypto.createCipheriv('aes-256-gcm',k,n),v=c.update(t,'utf8','hex')+c.final('hex');return{nonce:n.toString('hex'),tag:c.getAuthTag().toString('hex'),val:v};};
const dec=(k,n,t,v)=>{try{const c=crypto.createDecipheriv('aes-256-gcm',k,Buffer.from(n,'hex'));c.setAuthTag(Buffer.from(t,'hex'));return c.update(v,'hex','utf8')+c.final('utf8');}catch{return null;}};
const vr=()=>db.prepare('SELECT * FROM vault ORDER BY ts DESC LIMIT 50').all();
const emitServer=()=>{
const all=vr();
const mw=all.filter(r=>r.fromNode===nm||r.toNode===nm).map(r=>{const peer=r.fromNode===nm?r.toNode:r.fromNode;let pt='[awaiting key]';if(keys[peer])pt=dec(keys[peer],r.nonce,r.tag,r.val)||'[decrypt error]';return{...r,plaintext:pt};});
const lk=all.filter(r=>r.fromNode!==nm&&r.toNode!==nm);
io.emit('mywork',mw);
io.emit('locker',lk);
};
const store=m=>{try{db.prepare('INSERT OR IGNORE INTO vault(msgId,fromNode,toNode,nonce,tag,val,ts) VALUES(?,?,?,?,?,?,?)').run(m.id,m.from,m.to,m.nonce,m.tag,m.val,Date.now());}catch{}emitServer();};
const bcast=o=>{for(const p in socks){const arr=socks[p];if(arr.length>0)try{arr[0].write(JSON.stringify(o)+'\n');}catch{}}};
const handle=s=>{
s.write(JSON.stringify({t:'hello',n:nm,pk:myPk})+'\n');
let buf='';
s.on('data',d=>{buf+=d.toString();const ls=buf.split('\n');buf=ls.pop();ls.forEach(l=>{try{const m=JSON.parse(l);
if(m.t==='hello'&&m.n!==nm){if(!keys[m.n]){keys[m.n]=crypto.createHash('sha256').update(ecdh.computeSecret(Buffer.from(m.pk,'hex'))).digest();ready.add(m.n);io.emit('peer-ready',m.n);io.emit('sys',`ECDH secp256k1 handshake with Node ${m.n} → AES-256-GCM key derived`);if(ready.size>=pp.length)io.emit('mesh-ready');}if(!socks[m.n])socks[m.n]=[];if(!socks[m.n].includes(s))socks[m.n].push(s);}
if(m.t==='msg'&&!seen.has(m.id)){seen.add(m.id);store(m);if(m.to===nm&&keys[m.from]){const txt=dec(keys[m.from],m.nonce,m.tag,m.val);if(txt)io.emit('chat-msg',{from:m.from,text:txt,group:!!m.group});}}
}catch{}});});
s.on('close',()=>{for(const p in socks)socks[p]=socks[p].filter(x=>x!==s);});
s.on('error',()=>{});
};
const tryConn=port=>{const s=net.connect(parseInt(port),'127.0.0.1');s.on('connect',()=>handle(s));s.on('error',()=>setTimeout(()=>tryConn(port),500));};
net.createServer(s=>handle(s)).listen(parseInt(tcpP),()=>{pp.forEach(p=>setTimeout(()=>tryConn(p),300));});
app.use(express.static(__dirname+'/public'));
io.on('connection',s=>{
s.emit('init',{name:nm});
emitServer();
ready.forEach(p=>s.emit('peer-ready',p));
if(ready.size>=pp.length)s.emit('mesh-ready');
s.on('send-dm',d=>{if(!keys[d.to])return;const e=enc(keys[d.to],d.text),id=crypto.randomUUID(),m={t:'msg',id,from:nm,to:d.to,nonce:e.nonce,tag:e.tag,val:e.val};store(m);bcast(m);s.emit('chat-msg',{from:'Me',text:d.text,to:d.to});});
s.on('send-group',d=>{for(const p of Object.keys(keys)){const e=enc(keys[p],d.text),id=crypto.randomUUID(),m={t:'msg',id,from:nm,to:p,nonce:e.nonce,tag:e.tag,val:e.val,group:true};store(m);bcast(m);}s.emit('chat-msg',{from:'Me',text:d.text,group:true});});
});
http.listen(parseInt(uiP),()=>console.log(`Node ${nm} UI: ${uiP} | TCP: ${tcpP}`));
