import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import { extname, join, normalize, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('.', import.meta.url));
const PORT = Number(process.env.PORT || 3000);
const networks = {
  ethereum: { chainId: 1, name: 'Ethereum', rpc: process.env.ETHEREUM_RPC_URL || 'https://ethereum-rpc.publicnode.com', explorer: 'https://etherscan.io/address/' },
  base: { chainId: 8453, name: 'Base', rpc: process.env.BASE_RPC_URL || 'https://mainnet.base.org', explorer: 'https://basescan.org/address/' },
  arbitrum: { chainId: 42161, name: 'Arbitrum One', rpc: process.env.ARBITRUM_RPC_URL || 'https://arb1.arbitrum.io/rpc', explorer: 'https://arbiscan.io/address/' },
  optimism: { chainId: 10, name: 'Optimism', rpc: process.env.OPTIMISM_RPC_URL || 'https://mainnet.optimism.io', explorer: 'https://optimistic.etherscan.io/address/' }
};
const cache = new Map();
const requests = new Map();
const selectors = {
  '06fdde03':'name()', '95d89b41':'symbol()', '313ce567':'decimals()', '18160ddd':'totalSupply()',
  '70a08231':'balanceOf(address)', 'a9059cbb':'transfer(address,uint256)', '23b872dd':'transferFrom(address,address,uint256)',
  '095ea7b3':'approve(address,uint256)', 'dd62ed3e':'allowance(address,address)', '8da5cb5b':'owner()',
  'f2fde38b':'transferOwnership(address)', '715018a6':'renounceOwnership()', '5c975abb':'paused()',
  '8456cb59':'pause()', '3f4ba83a':'unpause()', '40c10f19':'mint(address,uint256)', '42966c68':'burn(uint256)',
  '3659cfe6':'upgradeTo(address)', '4f1ef286':'upgradeToAndCall(address,bytes)', 'b5312768':'admin()',
  '8f283970':'implementation()', 'e985e9c5':'proxiableUUID()'
};
const json = (res, status, data) => { res.writeHead(status, { 'content-type':'application/json; charset=utf-8', 'cache-control':'no-store', 'access-control-allow-origin':'*' }); res.end(JSON.stringify(data)); };
async function rpc(url, method, params=[]) {
  const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 10000);
  try { const r = await fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params}),signal:controller.signal}); if(!r.ok) throw Error(`RPC returned HTTP ${r.status}`); const d=await r.json(); if(d.error) throw Error(d.error.message||'RPC request failed'); return d.result; }
  finally { clearTimeout(timer); }
}
async function investigate({ address, network }) {
  const chain=networks[network]; if(!chain) throw Object.assign(Error('Choose a supported network.'),{status:400});
  if(typeof address!=='string'||!/^0x[a-fA-F0-9]{40}$/.test(address)) throw Object.assign(Error('Enter a valid EVM address: 0x followed by 40 hexadecimal characters.'),{status:400});
  const key=`${network}:${address.toLowerCase()}`; const saved=cache.get(key); if(saved && Date.now()-saved.time<60000) return {...saved.data,cached:true};
  const code=await rpc(chain.rpc,'eth_getCode',[address,'latest']);
  if(!code || code==='0x') throw Object.assign(Error('No contract bytecode was found at this address on '+chain.name+'. Check the address and network.'),{status:404});
  const bytecode=code.slice(2), bytes=bytecode.length/2;
  let source=null, sourceStatus='Unverified', sourceError=null;
  let sourcifyUnavailable=false;
  for(const match of ['full_match','partial_match']) {
    try {
      const ctrl=new AbortController(),timer=setTimeout(()=>ctrl.abort(),7000);
      const r=await fetch(`https://repo.sourcify.dev/contracts/${match}/${chain.chainId}/${address}/metadata.json`,{signal:ctrl.signal});
      clearTimeout(timer);
      if(r.ok){const metadata=await r.json();const files=[];let total=0;
        for(const filename of Object.keys(metadata.sources||{}).slice(0,20)){
          try{const sourceURL=`https://repo.sourcify.dev/contracts/${match}/${chain.chainId}/${address}/sources/${filename.split('/').map(encodeURIComponent).join('/')}`;const sr=await fetch(sourceURL,{signal:AbortSignal.timeout(4000)});if(sr.ok){const body=await sr.text();total+=body.length;if(total<=500000)files.push(body);}}catch{}
        }
        source={metadata,files};sourceStatus=match==='full_match'?'Fully verified source available':'Partially verified source available';break;
      }
    } catch { sourcifyUnavailable=true; }
  }
  if(sourcifyUnavailable) sourceError='Sourcify could not be reached; verification status may be unknown.';
  const found=new Set();
  for(let i=0;i<bytecode.length;){
    const opcode=parseInt(bytecode.slice(i,i+2),16); i+=2;
    if(opcode>=0x60&&opcode<=0x7f){const size=(opcode-0x5f)*2;if(opcode===0x63){const s=bytecode.slice(i,i+8).toLowerCase();if(s.length===8&&selectors[s])found.add(s);}i+=size;}
  }
  const abi=(source?.metadata?.output?.abi||[]).filter(x=>x.type==='function');
  const functions=abi.length ? abi.map(f=>({name:`${f.name}(${(f.inputs||[]).map(i=>i.type).join(',')})`,selector:null,confirmed:true})) : [...found].map(s=>({name:selectors[s],selector:'0x'+s,confirmed:false}));
  if(abi.length) for(const fn of functions){const signature=fn.name;const match=Object.entries(selectors).find(([,v])=>v===signature);if(match)fn.selector='0x'+match[0];}
  const text=(source?.files?source.files.join('\n'):'').toLowerCase();
  const has=(re)=>re.test(text);
  const permissionFindings=[];
  const hasFn=(needle)=>functions.some(f=>f.name.toLowerCase().startsWith(needle));
  if(hasFn('owner()')||has(/onlyowner|only_owner/))permissionFindings.push({title:'Owner-controlled actions may exist',severity:'Review',evidence:hasFn('owner()')?'Detected owner() function in contract interface.':'Verified source contains an onlyOwner-style access modifier.',confidence:source?'Source evidence':'Selector evidence'});
  if(hasFn('mint(')||has(/\bmint\s*\(/))permissionFindings.push({title:'Minting capability indicated',severity:'Review',evidence:hasFn('mint(')?'A mint function is present in the recovered interface or selectors.':'Verified source includes a mint function.',confidence:source?'Source evidence':'Selector evidence'});
  if(hasFn('pause(')||has(/\bpause\s*\(/))permissionFindings.push({title:'Pause controls indicated',severity:'Review',evidence:'Pause-related function identified; this does not establish who can call it.',confidence:source?'Source evidence':'Selector evidence'});
  if(hasFn('upgradeto(')||hasFn('upgradetoandcall('))permissionFindings.push({title:'Upgrade interface detected',severity:'Review',evidence:'An upgrade-related function signature was identified; authority and implementation are not confirmed.',confidence:source?'Source evidence':'Selector evidence'});
  let implementation=null, proxyEvidence=null;
  try {const slot='0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc';const value=await rpc(chain.rpc,'eth_getStorageAt',[address,slot,'latest']);if(value&&value!=='0x'+'0'.repeat(64)){const candidate='0x'+value.slice(-40);if(!/^0x0{40}$/i.test(candidate)){implementation=candidate;proxyEvidence='Non-zero value found in the EIP-1967 implementation storage slot.';}}}catch{}
  const result={address,network,networkName:chain.name,chainId:chain.chainId,explorer:chain.explorer+address,bytecodeBytes:bytes,codeHash:null,sourceStatus,sourceError,contractName:source?.metadata?.settings?.compilationTarget?Object.values(source.metadata.settings.compilationTarget)[0]:null,compiler:source?.metadata?.compiler?.version||null,verified:!!source,functions,permissions:permissionFindings,implementation,proxyEvidence,dependencies:[],analysisDepth:source?'Verified source metadata and ABI; static interface inspection.':'Deployed bytecode and recognized function selectors only.',limitations:['Function selectors do not prove a function implementation or caller permissions.','No transaction traces, full decompilation, or interaction graph were retrieved.','Absence of a finding is not evidence that a capability is absent.',...(sourceError?[sourceError]:[])],timestamp:new Date().toISOString(),bytecodePreview:'0x'+bytecode.slice(0,160)+(bytecode.length>160?'…':'')};
  try { const crypto=await import('node:crypto'); result.codeHash='0x'+crypto.createHash('sha256').update(Buffer.from(bytecode,'hex')).digest('hex'); } catch{}
  cache.set(key,{time:Date.now(),data:result});return result;
}
const mime={'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.svg':'image/svg+xml'};
createServer(async(req,res)=>{
  if(req.method==='OPTIONS'){res.writeHead(204,{'access-control-allow-origin':'*','access-control-allow-methods':'POST, OPTIONS','access-control-allow-headers':'content-type'});return res.end();}
  if(req.method==='POST'&&req.url==='/api/investigate'){
    try{
      const ip=req.socket.remoteAddress||'unknown',now=Date.now(),entry=requests.get(ip)||{start:now,count:0};
      if(now-entry.start>60000){entry.start=now;entry.count=0;}
      entry.count++;requests.set(ip,entry);
      if(entry.count>30)throw Object.assign(Error('Too many requests. Please wait a minute and retry.'),{status:429});
      let body='';for await(const chunk of req){body+=chunk;if(body.length>4096)throw Object.assign(Error('Request is too large.'),{status:413});}
      const input=JSON.parse(body);json(res,200,await investigate(input));
    }
    catch(e){json(res,e.status||502,{error:e.name==='AbortError'?'The network provider timed out. Please retry.':e.message||'Unable to retrieve contract data. Please retry.',retryable:!e.status});}return;
  }
  let raw;try{raw=decodeURIComponent((req.url||'/').split('?')[0]);}catch{res.writeHead(400);return res.end('Bad request');}
  const path=raw==='/'?'index.html':normalize(raw).replace(/^([/\\])+/, '');const file=resolve(join(root,path));
  if(file!==root&&!file.startsWith(root+sep)){res.writeHead(403);return res.end('Forbidden');}
  try{await readFile(file);res.writeHead(200,{'content-type':mime[extname(file)]||'application/octet-stream'});createReadStream(file).pipe(res);}catch{res.writeHead(404);res.end('Not found');}
}).listen(PORT,()=>console.log(`BYTEWORLD running at http://localhost:${PORT}`));
