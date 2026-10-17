const networks = {
  ethereum: { chainId: 1, name: 'Ethereum Mainnet', rpc: process.env.ETHEREUM_RPC_URL || 'https://ethereum-rpc.publicnode.com', explorer: 'https://etherscan.io/address/' },
  base: { chainId: 8453, name: 'Base', rpc: process.env.BASE_RPC_URL || 'https://mainnet.base.org', explorer: 'https://basescan.org/address/' },
  arbitrum: { chainId: 42161, name: 'Arbitrum One', rpc: process.env.ARBITRUM_RPC_URL || 'https://arb1.arbitrum.io/rpc', explorer: 'https://arbiscan.io/address/' },
  optimism: { chainId: 10, name: 'Optimism', rpc: process.env.OPTIMISM_RPC_URL || 'https://mainnet.optimism.io', explorer: 'https://optimistic.etherscan.io/address/' }
};
const selectors = {
  '06fdde03':'name()', '95d89b41':'symbol()', '313ce567':'decimals()', '18160ddd':'totalSupply()',
  '70a08231':'balanceOf(address)', 'a9059cbb':'transfer(address,uint256)', '23b872dd':'transferFrom(address,address,uint256)',
  '095ea7b3':'approve(address,uint256)', 'dd62ed3e':'allowance(address,address)', '8da5cb5b':'owner()',
  'f2fde38b':'transferOwnership(address)', '715018a6':'renounceOwnership()', '5c975abb':'paused()',
  '8456cb59':'pause()', '3f4ba83a':'unpause()', '40c10f19':'mint(address,uint256)', '42966c68':'burn(uint256)',
  '3659cfe6':'upgradeTo(address)', '4f1ef286':'upgradeToAndCall(address,bytes)', 'b5312768':'admin()',
  '8f283970':'implementation()', 'e985e9c5':'proxiableUUID()'
};
const cache = new Map();

async function rpc(url, method, params = []) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }), signal: controller.signal });
    if (!response.ok) throw new Error(`RPC returned HTTP ${response.status}`);
    const data = await response.json();
    if (data.error) throw new Error(data.error.message || 'RPC request failed');
    return data.result;
  } finally { clearTimeout(timer); }
}

async function analyze(address, network) {
  if (typeof address !== 'string' || !/^0x[a-fA-F0-9]{40}$/.test(address)) throw Object.assign(new Error('Enter a valid EVM address: 0x followed by 40 hexadecimal characters.'), { statusCode: 400 });
  const chain = networks[network];
  if (!chain) throw Object.assign(new Error('Choose a supported network.'), { statusCode: 400 });
  const key = `${network}:${address.toLowerCase()}`;
  const cached = cache.get(key);
  if (cached && Date.now() - cached.time < 60000) return { ...cached.data, cached: true };

  const bytecode = await rpc(chain.rpc, 'eth_getCode', [address, 'latest']);
  if (!bytecode || bytecode === '0x') throw Object.assign(new Error(`No contract bytecode was found at this address on ${chain.name}. Check the address and network.`), { statusCode: 404 });
  const rawCode = bytecode.slice(2);
  let source = null, sourceError = null, sourcifyUnavailable = false;
  for (const match of ['full_match', 'partial_match']) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 7000);
      const response = await fetch(`https://repo.sourcify.dev/contracts/${match}/${chain.chainId}/${address}/metadata.json`, { signal: controller.signal });
      clearTimeout(timer);
      if (!response.ok) continue;
      const metadata = await response.json(), files = [];
      for (const filename of Object.keys(metadata.sources || {}).slice(0, 20)) {
        try {
          const path = filename.split('/').map(encodeURIComponent).join('/');
          const file = await fetch(`https://repo.sourcify.dev/contracts/${match}/${chain.chainId}/${address}/sources/${path}`, { signal: AbortSignal.timeout(4000) });
          if (file.ok) { const text = await file.text(); if (files.join('').length + text.length < 500000) files.push(text); }
        } catch { /* Source excerpts are optional; metadata and ABI remain useful. */ }
      }
      source = { metadata, files };
      break;
    } catch { sourcifyUnavailable = true; }
  }
  if (sourcifyUnavailable) sourceError = 'Sourcify could not be reached; verification status may be unknown.';

  const found = new Set();
  for (let i = 0; i < rawCode.length;) {
    const opcode = parseInt(rawCode.slice(i, i + 2), 16); i += 2;
    if (opcode >= 0x60 && opcode <= 0x7f) {
      const size = (opcode - 0x5f) * 2;
      if (opcode === 0x63) { const selector = rawCode.slice(i, i + 8).toLowerCase(); if (selector.length === 8 && selectors[selector]) found.add(selector); }
      i += size;
    }
  }
  const abi = (source?.metadata?.output?.abi || []).filter(item => item.type === 'function');
  const functions = abi.length ? abi.map(fn => ({ name: `${fn.name}(${(fn.inputs || []).map(input => input.type).join(',')})`, selector: null, confirmed: true })) : [...found].map(selector => ({ name: selectors[selector], selector: `0x${selector}`, confirmed: false }));
  for (const fn of functions) { const signature = Object.entries(selectors).find(([, name]) => name === fn.name); if (signature) fn.selector = `0x${signature[0]}`; }
  const sourceText = (source?.files || []).join('\n').toLowerCase();
  const hasFunction = prefix => functions.some(fn => fn.name.toLowerCase().startsWith(prefix));
  const permissions = [];
  const add = (title, evidence) => permissions.push({ title, severity: 'Review', evidence, confidence: source ? 'Source evidence' : 'Selector evidence' });
  if (hasFunction('owner()') || /onlyowner|only_owner/.test(sourceText)) add('Owner-controlled actions may exist', hasFunction('owner()') ? 'Detected owner() in the recovered contract interface; this does not establish what the owner can control.' : 'Verified source contains an onlyOwner-style modifier; current authority is not established.');
  if (hasFunction('mint(') || /\bmint\s*\(/.test(sourceText)) add('Minting capability indicated', 'A mint-related signature or verified-source pattern was identified; caller permissions are not confirmed.');
  if (hasFunction('pause(') || /\bpause\s*\(/.test(sourceText)) add('Pause controls indicated', 'A pause-related signature or verified-source pattern was identified; caller permissions are not confirmed.');
  if (hasFunction('upgradeto(') || hasFunction('upgradetoandcall(')) add('Upgrade interface detected', 'An upgrade-related function signature was identified; authority and implementation are not confirmed.');

  let implementation = null, proxyEvidence = null;
  try {
    const slot = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc';
    const value = await rpc(chain.rpc, 'eth_getStorageAt', [address, slot, 'latest']);
    if (value && value !== `0x${'0'.repeat(64)}`) {
      const candidate = `0x${value.slice(-40)}`;
      if (!/^0x0{40}$/i.test(candidate)) { implementation = candidate; proxyEvidence = 'Non-zero value found in the EIP-1967 implementation storage slot.'; }
    }
  } catch { /* A failed optional proxy check does not invalidate bytecode retrieval. */ }

  const result = {
    address, network, networkName: chain.name, chainId: chain.chainId, explorer: chain.explorer + address,
    bytecodeBytes: rawCode.length / 2, codeHash: null,
    sourceStatus: source ? (source.metadata?.settings?.compilationTarget ? 'Verified source available' : 'Verified metadata available') : 'Unverified',
    sourceError, contractName: source?.metadata?.settings?.compilationTarget ? Object.values(source.metadata.settings.compilationTarget)[0] : null,
    compiler: source?.metadata?.compiler?.version || null, verified: Boolean(source), functions, permissions, implementation, proxyEvidence, dependencies: [],
    analysisDepth: source ? 'Verified source metadata and ABI; static interface inspection.' : 'Deployed bytecode and recognized function selectors only.',
    limitations: ['Function selectors do not prove a function implementation or caller permissions.', 'No transaction traces, full decompilation, or interaction graph were retrieved.', 'Absence of a finding is not evidence that a capability is absent.', ...(sourceError ? [sourceError] : [])],
    timestamp: new Date().toISOString(), bytecodePreview: `0x${rawCode.slice(0, 160)}${rawCode.length > 160 ? '…' : ''}`
  };
  try { const { createHash } = await import('node:crypto'); result.codeHash = `0x${createHash('sha256').update(Buffer.from(rawCode, 'hex')).digest('hex')}`; } catch { /* Hash is optional. */ }
  cache.set(key, { time: Date.now(), data: result });
  return result;
}

export default async (request) => {
  if (request.httpMethod !== 'POST') return { statusCode: 405, headers: { 'content-type': 'application/json', allow: 'POST' }, body: JSON.stringify({ error: 'Method not allowed.' }) };
  if ((request.body || '').length > 4096) return { statusCode: 413, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ error: 'Request is too large.' }) };
  try {
    const input = JSON.parse(request.body || '{}');
    const result = await analyze(input.address, input.network);
    return { statusCode: 200, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' }, body: JSON.stringify(result) };
  } catch (error) {
    const statusCode = error.statusCode || 502;
    const message = error.name === 'AbortError' ? 'The network provider timed out. Please retry.' : error.message || 'Unable to retrieve contract data. Please retry.';
    return { statusCode, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' }, body: JSON.stringify({ error: message, retryable: !error.statusCode }) };
  }
};
