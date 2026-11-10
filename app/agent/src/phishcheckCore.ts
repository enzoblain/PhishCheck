/**
 * phishcheck core (no LLM, no Node APIs, also bundled for the browser):
 * deterministic, read-only address-poisoning / phishing analysis.
 *
 * Given a DESTINATION address (where the user is about to send funds) and,
 * optionally, the user's own WALLET, it gathers on-chain facts over plain
 * JSON-RPC and turns them into a risk verdict (green / orange / red) with
 * reasons. The LLM only rewrites this report in plain language; it never
 * decides the facts.
 *
 * Signals:
 *  - destination profile: contract vs EOA, nonce, native balance
 *  - poisoning bot behaviour: many zero-value stablecoin transfers involving
 *    the destination across many distinct counterparties
 *  - wallet history (if WALLET given): is the destination a real past
 *    counterparty, only a zero/dust counterparty, or a LOOKALIKE of one
 *    (same leading + trailing hex chars, the classic poisoning trick)
 *
 * Public RPCs require a token `address` filter on eth_getLogs and cap the
 * block range, so we scan the main stablecoins over a bounded recent window.
 */

/** Env lookup that also works in the browser bundle (no `process`). */
const env = (k: string): string | undefined =>
  (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env?.[k];

export type Network = "bsc-mainnet" | "bsc-testnet";
export type Level = "green" | "orange" | "red";

const TRANSFER_TOPIC =
  "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

const RPCS: Record<Network, string[]> = {
  "bsc-mainnet": [
    env("PHISHCHECK_BSC_RPC") ?? "https://bsc-rpc.publicnode.com",
    "https://bsc-rpc.publicnode.com",
  ],
  "bsc-testnet": [
    env("PHISHCHECK_BSC_TESTNET_RPC") ?? "https://bsc-testnet.publicnode.com",
    "https://bsc-testnet.publicnode.com",
    "https://bsc-testnet-dataseed.bnbchain.org",
  ],
};

/** Stablecoins most used for poisoning (zero-value transferFrom / dust). */
const TOKENS: Record<Network, Record<string, string>> = {
  "bsc-mainnet": {
    USDT: "0x55d398326f99059fF775485246999027B3197955",
    USDC: "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d",
    FDUSD: "0xc5f0f7b66764F6ec8C8Dff7BA683102295E16409",
    BUSD: "0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56",
    U: "0xcE24439F2D9C6a2289F741120FE202248B666666",
  },
  "bsc-testnet": {
    U: "0xc70B8741B8B07A6d61E54fd4B20f22Fa648E5565",
  },
};

/** Blocks per eth_getLogs call (public cap is 50k) and number of chunks. */
const CHUNK = 45_000;
const CHUNKS = 3; // ~135k blocks ≈ 16h at BSC's ~0.45s block time
/** Below this many base units (18-dec ≈ 0.01 token) a transfer counts as dust. */
const DUST = 10n ** 16n;

// ── JSON-RPC ──────────────────────────────────────────────────────────────────

async function rpc<T>(net: Network, method: string, params: unknown[]): Promise<T> {
  let lastErr: unknown;
  for (const url of [...new Set(RPCS[net])]) {
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
        signal: AbortSignal.timeout(20_000),
      });
      const body = (await res.json()) as { result?: T; error?: { message: string } };
      if (body.error) throw new Error(`${method}: ${body.error.message}`);
      return body.result as T;
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr instanceof Error ? lastErr : new Error(String(lastErr));
}

interface Log {
  address: string;
  topics: string[];
  data: string;
  blockNumber: string;
  transactionHash: string;
}

const pad = (a: string) => "0x" + a.toLowerCase().slice(2).padStart(64, "0");
const unpad = (t: string) => ("0x" + t.slice(-40)).toLowerCase();

async function transferLogs(
  net: Network,
  who: string,
  side: "from" | "to",
  latest: number,
): Promise<Log[]> {
  const topics =
    side === "from" ? [TRANSFER_TOPIC, pad(who)] : [TRANSFER_TOPIC, null, pad(who)];
  const address = Object.values(TOKENS[net]);
  const jobs: Promise<Log[]>[] = [];
  for (let i = 0; i < CHUNKS; i++) {
    const to = latest - i * CHUNK;
    const from = Math.max(0, to - CHUNK + 1);
    jobs.push(
      rpc<Log[]>(net, "eth_getLogs", [
        { fromBlock: "0x" + from.toString(16), toBlock: "0x" + to.toString(16), address, topics },
      ]).catch(() => []), // one failed window must not sink the whole check
    );
  }
  return (await Promise.all(jobs)).flat();
}

// ── Analysis ──────────────────────────────────────────────────────────────────

export interface Finding {
  level: Level;
  text: string;
}

export interface Report {
  network: Network;
  destination: string;
  wallet: string | null;
  scannedBlocks: number;
  destinationProfile: {
    isContract: boolean;
    nonce: number;
    balanceBnb: string;
  };
  findings: Finding[];
  /** Closest lookalike from the wallet's history, if any. */
  lookalike: { address: string; head: number; tail: number; destIsGenuine: boolean } | null;
  verdict: Level;
}

const ADDR_RE = /0x[0-9a-fA-F]{40}/g;

/** Leading/trailing hex chars two addresses share (after 0x). */
function sharedEnds(a: string, b: string): { head: number; tail: number } {
  const x = a.toLowerCase().slice(2);
  const y = b.toLowerCase().slice(2);
  let head = 0;
  while (head < 40 && x[head] === y[head]) head++;
  let tail = 0;
  while (tail < 40 && x[39 - tail] === y[39 - tail]) tail++;
  return { head, tail };
}

const symbolOf = (net: Network, token: string) =>
  Object.entries(TOKENS[net]).find(([, a]) => a.toLowerCase() === token.toLowerCase())?.[0] ??
  token;

export function parseRequest(prompt: string): {
  destination: string | null;
  wallet: string | null;
  network: Network;
} {
  const addrs = [...new Set((prompt.match(ADDR_RE) ?? []).map((a) => a.toLowerCase()))];
  const network: Network = /testnet/i.test(prompt) ? "bsc-testnet" : "bsc-mainnet";
  return { destination: addrs[0] ?? null, wallet: addrs[1] ?? null, network };
}

export async function analyze(
  destination: string,
  wallet: string | null,
  network: Network,
): Promise<Report> {
  const dest = destination.toLowerCase();
  const me = wallet?.toLowerCase() ?? null;
  const findings: Finding[] = [];
  let lookalike: Report["lookalike"] = null;

  const latest = parseInt(await rpc<string>(network, "eth_blockNumber", []), 16);
  const [code, nonceHex, balHex, destOut, destIn, myOut, myIn] = await Promise.all([
    rpc<string>(network, "eth_getCode", [dest, "latest"]),
    rpc<string>(network, "eth_getTransactionCount", [dest, "latest"]),
    rpc<string>(network, "eth_getBalance", [dest, "latest"]),
    transferLogs(network, dest, "from", latest),
    transferLogs(network, dest, "to", latest),
    me ? transferLogs(network, me, "from", latest) : Promise.resolve([]),
    me ? transferLogs(network, me, "to", latest) : Promise.resolve([]),
  ]);

  const isContract = code !== "0x" && code !== "0x0";
  const nonce = parseInt(nonceHex, 16);
  const balanceWei = BigInt(balHex);
  const balanceBnb = (Number(balanceWei) / 1e18).toFixed(6);

  // 1. Destination profile
  if (me && dest === me) {
    findings.push({ level: "orange", text: "The destination is your own wallet." });
  }
  if (isContract) {
    const isToken = Object.values(TOKENS[network]).some((a) => a.toLowerCase() === dest);
    findings.push({
      level: isToken ? "red" : "orange",
      text: isToken
        ? `The destination is the ${symbolOf(network, dest)} TOKEN CONTRACT itself — tokens sent there are lost forever.`
        : "The destination is a smart contract, not a personal wallet. Only send if you know exactly what this contract does.",
    });
  } else if (nonce === 0 && balanceWei === 0n) {
    findings.push({
      level: "orange",
      text: "The destination has never sent a transaction and holds 0 BNB: it is brand new or unused. Double-check it with the recipient through another channel.",
    });
  } else if (nonce === 0) {
    findings.push({
      level: "orange",
      text: "The destination has never sent a transaction itself (receive-only so far).",
    });
  } else {
    findings.push({
      level: "green",
      text: `The destination is an active wallet (${nonce} transactions sent).`,
    });
  }

  // 2. Poisoning-bot behaviour: zero/dust stablecoin transfers involving dest
  const destLogs = [...destOut, ...destIn];
  const zeroish = destLogs.filter((l) => BigInt(l.data === "0x" ? 0 : l.data) < DUST);
  const zeroCounterparties = new Set(
    zeroish.map((l) => {
      const from = unpad(l.topics[1]!);
      const to = unpad(l.topics[2]!);
      return from === dest ? to : from;
    }),
  );
  if (zeroCounterparties.size >= 5) {
    findings.push({
      level: "red",
      text: `The destination was involved in ${zeroish.length} zero-value or dust stablecoin transfers with ${zeroCounterparties.size} different wallets in the last ~${CHUNK * CHUNKS} blocks. That is the signature of an address-poisoning bot.`,
    });
  } else if (zeroish.length > 0) {
    findings.push({
      level: "orange",
      text: `The destination appears in ${zeroish.length} zero-value or dust stablecoin transfer(s) recently. Legitimate wallets rarely do this.`,
    });
  }

  // 3. Wallet history: real counterparties vs zero-only vs lookalikes
  if (me) {
    const real = new Set<string>(); // counterparties with a meaningful transfer
    const zeroOnly = new Set<string>(); // counterparties seen only via 0/dust
    for (const l of [...myOut, ...myIn]) {
      const from = unpad(l.topics[1]!);
      const to = unpad(l.topics[2]!);
      const other = from === me ? to : from;
      const value = BigInt(l.data === "0x" ? 0 : l.data);
      if (value >= DUST) real.add(other);
      else zeroOnly.add(other);
    }
    for (const r of real) zeroOnly.delete(r);

    if (real.has(dest)) {
      findings.push({
        level: "green",
        text: "You have already exchanged real stablecoin amounts with this exact address recently.",
      });
    } else if (zeroOnly.has(dest)) {
      findings.push({
        level: "red",
        text: "This address only ever sent/received ZERO or dust amounts with your wallet. It was planted in your history: do NOT copy addresses from your transaction list.",
      });
    }

    let best: { addr: string; head: number; tail: number } | null = null;
    for (const c of [...real, ...zeroOnly]) {
      if (c === dest) continue;
      const s = sharedEnds(dest, c);
      if (s.head >= 3 && s.tail >= 3 && (!best || s.head + s.tail > best.head + best.tail)) {
        best = { addr: c, ...s };
      }
    }
    if (best) {
      lookalike = { address: best.addr, head: best.head, tail: best.tail, destIsGenuine: real.has(dest) };
    }
    if (best && real.has(dest)) {
      // dest is the genuine counterparty; the lookalike is the planted copy.
      findings.push({
        level: "orange",
        text: `Your history also contains a LOOKALIKE of this address (${best.addr}, first ${best.head} / last ${best.tail} characters identical). This one is the address you really paid, but someone is trying to poison your history: always copy it from a trusted source, never from your transaction list.`,
      });
    } else if (best) {
      findings.push({
        level: "red",
        text: `LOOKALIKE: the destination shares its first ${best.head} and last ${best.tail} characters with ${best.addr}, an address from your recent history${real.has(best.addr) ? " that you really paid" : ""}. This is the classic address-poisoning trick; compare every character.`,
      });
    }
    if (!real.has(dest) && !zeroOnly.has(dest) && !best) {
      findings.push({
        level: "green",
        text: "No lookalike of this address was found in your recent stablecoin history.",
      });
    }
  }

  const verdict: Level = findings.some((f) => f.level === "red")
    ? "red"
    : findings.some((f) => f.level === "orange")
      ? "orange"
      : "green";

  return {
    network,
    destination: dest,
    wallet: me,
    scannedBlocks: CHUNK * CHUNKS,
    destinationProfile: { isContract, nonce, balanceBnb },
    findings,
    lookalike,
    verdict,
  };
}

const EMOJI: Record<Level, string> = { green: "🟢", orange: "🟠", red: "🔴" };

/** Plain-text report, used as the deliverable fallback if the LLM fails. */
export function formatReport(r: Report): string {
  return [
    `${EMOJI[r.verdict]} phishcheck verdict: ${r.verdict.toUpperCase()}`,
    `Destination: ${r.destination} (${r.network})`,
    r.wallet ? `Your wallet: ${r.wallet}` : "Your wallet: not provided (lookalike check skipped)",
    "",
    ...r.findings.map((f) => `${EMOJI[f.level]} ${f.text}`),
    "",
    `Scanned the last ~${r.scannedBlocks} blocks of ${Object.keys(TOKENS[r.network]).join("/")} transfers.`,
  ].join("\n");
}

