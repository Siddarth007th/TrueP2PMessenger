const {spawn,exec}=require('child_process'),path=require('path'),fs=require('fs');
['A','B','C'].forEach(n=>{try{fs.unlinkSync(path.join(__dirname,`node-${n}.db`));}catch{}});
const nodes=[['A','3001','4001','4002','4003'],['B','3002','4002','4001','4003'],['C','3003','4003','4001','4002']];
const go=i=>{
if(i>=nodes.length)return;
const n=nodes[i];
spawn('node',[path.join(__dirname,'node-daemon.js'),...n],{stdio:'inherit'});
setTimeout(()=>{exec(`open http://localhost:${n[1]}`);exec(`open http://localhost:${n[1]}/server.html`);},1500);
setTimeout(()=>go(i+1),600);
};
go(0);
