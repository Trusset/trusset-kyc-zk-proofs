// The IdentityHub, read-only: calldata the operator signs elsewhere, and
// eth_call reads for `verify --rpc-url`. Nothing here signs or sends a
// transaction.
//
// Hub functions used (identity contracts, `IdentityHub.sol`):
//   setAttesterProfile(bytes32 operatorKey, bytes32 leiHash, string metadataURI)
//   operatorKeyAt(address attester, uint32 keyId) view returns (bytes32)
//   getAttestation(address attester, address subject) view returns
//     (bytes32 root, uint128 predicates, uint32 issuedAt, uint32 softExpiry,
//      uint32 hardExpiry, uint8 investorClass, uint8 status)

import { keccak_256 } from '@noble/hashes/sha3';

export const HUB_STATUS = ['NONE', 'ACTIVE', 'SUSPENDED', 'REVOKED'] as const;

function hexOf(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

export function selector(signature: string): string {
  return hexOf(keccak_256(new TextEncoder().encode(signature))).slice(0, 8);
}

function word(hexNoPrefix: string): string {
  if (hexNoPrefix.length > 64) throw new Error('ABI word overflow');
  return hexNoPrefix.padStart(64, '0');
}

function encodeAddress(addr: string): string {
  if (!/^0x[0-9a-fA-F]{40}$/.test(addr)) throw new Error(`not an address: ${addr}`);
  return word(addr.slice(2).toLowerCase());
}

function encodeUint(n: number | bigint): string {
  const v = BigInt(n);
  if (v < 0n) throw new Error('negative uint');
  return word(v.toString(16));
}

function encodeBytes32(hex: string): string {
  const body = hex.replace(/^0x/i, '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(body)) throw new Error(`not 32 bytes of hex: ${hex}`);
  return body;
}

/** keccak256 of a UTF-8 string, 0x-prefixed. */
export function keccakHex(text: string): string {
  return '0x' + hexOf(keccak_256(new TextEncoder().encode(text)));
}

/**
 * Calldata for `setAttesterProfile`. The hub assigns the key id itself:
 * previous id + 1 when the key changes, 1 for an attester's first key.
 */
export function setAttesterProfileCalldata(operatorKeyHex: string, leiHashHex: string, metadataUri: string): string {
  const uri = Buffer.from(metadataUri, 'utf-8');
  if (uri.length > 512) throw new Error('metadataURI is longer than the hub allows (512 bytes)');
  const padded = uri.toString('hex').padEnd(Math.ceil(uri.length / 32) * 64, '0');
  return (
    '0x' +
    selector('setAttesterProfile(bytes32,bytes32,string)') +
    encodeBytes32(operatorKeyHex) +
    encodeBytes32(leiHashHex) +
    encodeUint(0x60) +
    encodeUint(uri.length) +
    padded
  );
}

export function operatorKeyAtCalldata(attester: string, keyId: number): string {
  return '0x' + selector('operatorKeyAt(address,uint32)') + encodeAddress(attester) + encodeUint(keyId);
}

export function getAttestationCalldata(attester: string, subject: string): string {
  return '0x' + selector('getAttestation(address,address)') + encodeAddress(attester) + encodeAddress(subject);
}

export interface HubAttestation {
  root: string;
  predicates: string;
  issuedAt: number;
  softExpiry: number;
  hardExpiry: number;
  investorClass: number;
  status: (typeof HUB_STATUS)[number] | string;
}

export function decodeAttestation(returnData: string): HubAttestation {
  const body = returnData.replace(/^0x/i, '');
  if (body.length < 7 * 64) throw new Error('getAttestation returned too little data');
  const w = (i: number) => body.slice(i * 64, (i + 1) * 64);
  const n = (i: number) => BigInt('0x' + w(i));
  const status = Number(n(6));
  return {
    root: '0x' + w(0),
    predicates: n(1).toString(10),
    issuedAt: Number(n(2)),
    softExpiry: Number(n(3)),
    hardExpiry: Number(n(4)),
    investorClass: Number(n(5)),
    status: HUB_STATUS[status] ?? String(status),
  };
}

let rpcId = 0;

/** One JSON-RPC call. Read-only methods only. */
export async function rpc(url: string, method: 'eth_call' | 'eth_chainId', params: unknown[]): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15_000);
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcId, method, params }),
      signal: controller.signal,
    });
    if (!res.ok) throw new Error(`RPC ${method}: HTTP ${res.status}`);
    const body = (await res.json()) as { result?: string; error?: { message?: string } };
    if (body.error) throw new Error(`RPC ${method}: ${body.error.message ?? 'error'}`);
    if (typeof body.result !== 'string') throw new Error(`RPC ${method}: no result`);
    return body.result;
  } finally {
    clearTimeout(timer);
  }
}

export interface ChainReadInput {
  rpcUrl: string;
  chainId: number;
  hub: string;
  attester: string;
  keyId: number;
  subject: string;
}

export interface ChainReadResult {
  chainId: number;
  operatorKey: string;
  attestation: HubAttestation;
}

/** Read what the hub holds for this subject and key id. Never writes. */
export async function readHub(input: ChainReadInput): Promise<ChainReadResult> {
  const chainHex = await rpc(input.rpcUrl, 'eth_chainId', []);
  const chainId = Number(BigInt(chainHex));
  if (chainId !== input.chainId) {
    throw new Error(`The RPC endpoint serves chain ${chainId}; the bundle is bound to chain ${input.chainId}.`);
  }
  const keyWord = await rpc(input.rpcUrl, 'eth_call', [
    { to: input.hub, data: operatorKeyAtCalldata(input.attester, input.keyId) },
    'latest',
  ]);
  const attestation = decodeAttestation(
    await rpc(input.rpcUrl, 'eth_call', [
      { to: input.hub, data: getAttestationCalldata(input.attester, input.subject) },
      'latest',
    ]),
  );
  return { chainId, operatorKey: '0x' + keyWord.replace(/^0x/i, '').padStart(64, '0').slice(-64), attestation };
}

export interface ExpectedAttestation {
  root: string;
  investorClass: number;
  predicates: string;
  softExpiry: number;
  hardExpiry: number;
}

/** Field-by-field comparison of the hub record with what the bundle supports. */
export function compareAttestation(onChain: HubAttestation, expected: ExpectedAttestation): string[] {
  const problems: string[] = [];
  if (onChain.status !== 'ACTIVE') problems.push(`hub status is ${onChain.status}, not ACTIVE`);
  if (onChain.root.toLowerCase() !== expected.root.toLowerCase()) {
    problems.push(`hub root ${onChain.root} is not this bundle's root ${expected.root}`);
  }
  if (onChain.investorClass !== expected.investorClass) {
    problems.push(`hub investorClass ${onChain.investorClass}, bundle proves ${expected.investorClass}`);
  }
  // Bits 0..63 are the public table and must equal what the bundle proves;
  // 64..127 are attester-defined and outside this bundle.
  const stdMask = (1n << 64n) - 1n;
  const hub = BigInt(onChain.predicates) & stdMask;
  const proven = BigInt(expected.predicates) & stdMask;
  if (hub !== proven) {
    problems.push(
      `hub predicates ${hub.toString(10)} differ from the ${proven.toString(10)} this bundle proves (bits the hub sets without a leaf: ${(hub & ~proven).toString(2)}, bits it leaves out: ${(proven & ~hub).toString(2)}, binary)`,
    );
  }
  if (onChain.softExpiry !== expected.softExpiry || onChain.hardExpiry !== expected.hardExpiry) {
    problems.push(
      `hub expiries ${onChain.softExpiry}/${onChain.hardExpiry} differ from the bundle's ${expected.softExpiry}/${expected.hardExpiry}`,
    );
  }
  return problems;
}
