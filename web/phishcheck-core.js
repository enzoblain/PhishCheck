// app/agent/src/phishcheckCore.ts
var env = (k) => globalThis.process?.env?.[k];
var TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
var RPCS = {
  "bsc-mainnet": [
    env("PHISHCHECK_BSC_RPC") ?? "https://bsc-rpc.publicnode.com",
    "https://bsc-rpc.publicnode.com"
  ],
  "bsc-testnet": [
    env("PHISHCHECK_BSC_TESTNET_RPC") ?? "https://bsc-testnet.publicnode.com",
    "https://bsc-testnet.publicnode.com",
    "https://bsc-testnet-dataseed.bnbchain.org"
  ]
};
var TOKENS = {
  "bsc-mainnet": {
    USDT: "0x55d398326f99059fF775485246999027B3197955",
    USDC: "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d",
    FDUSD: "0xc5f0f7b66764F6ec8C8Dff7BA683102295E16409",
    BUSD: "0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56",
    U: "0xcE24439F2D9C6a2289F741120FE202248B666666"
  },
  "bsc-testnet": {
    U: "0xc70B8741B8B07A6d61E54fd4B20f22Fa648E5565"
  }
};
var CHUNK = 45e3;
var CHUNKS = 3;
var DUST = 10n ** 16n;
async function rpc(net, method, params) {
  let lastErr;
  for (const url of [...new Set(RPCS[net])]) {
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
        signal: AbortSignal.timeout(2e4)
      });
      const body = await res.json();
      if (body.error) throw new Error(`${method}: ${body.error.message}`);
      return body.result;
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr instanceof Error ? lastErr : new Error(String(lastErr));
}
var pad = (a) => "0x" + a.toLowerCase().slice(2).padStart(64, "0");
var unpad = (t) => ("0x" + t.slice(-40)).toLowerCase();
async function transferLogs(net, who, side, latest) {
  const topics = side === "from" ? [TRANSFER_TOPIC, pad(who)] : [TRANSFER_TOPIC, null, pad(who)];
  const address = Object.values(TOKENS[net]);
  const jobs = [];
  for (let i = 0; i < CHUNKS; i++) {
    const to = latest - i * CHUNK;
    const from = Math.max(0, to - CHUNK + 1);
    jobs.push(
      rpc(net, "eth_getLogs", [
        { fromBlock: "0x" + from.toString(16), toBlock: "0x" + to.toString(16), address, topics }
      ]).catch(() => [])
      // one failed window must not sink the whole check
    );
  }
  return (await Promise.all(jobs)).flat();
}
var ADDR_RE = /0x[0-9a-fA-F]{40}/g;
function sharedEnds(a, b) {
  const x = a.toLowerCase().slice(2);
  const y = b.toLowerCase().slice(2);
  let head = 0;
  while (head < 40 && x[head] === y[head]) head++;
  let tail = 0;
  while (tail < 40 && x[39 - tail] === y[39 - tail]) tail++;
  return { head, tail };
}
var symbolOf = (net, token) => Object.entries(TOKENS[net]).find(([, a]) => a.toLowerCase() === token.toLowerCase())?.[0] ?? token;
function parseRequest(prompt) {
  const addrs = [...new Set((prompt.match(ADDR_RE) ?? []).map((a) => a.toLowerCase()))];
  const network = /testnet/i.test(prompt) ? "bsc-testnet" : "bsc-mainnet";
  return { destination: addrs[0] ?? null, wallet: addrs[1] ?? null, network };
}
async function analyze(destination, wallet, network) {
  const dest = destination.toLowerCase();
  const me = wallet?.toLowerCase() ?? null;
  const findings = [];
  let lookalike = null;
  const latest = parseInt(await rpc(network, "eth_blockNumber", []), 16);
  const [code, nonceHex, balHex, destOut, destIn, myOut, myIn] = await Promise.all([
    rpc(network, "eth_getCode", [dest, "latest"]),
    rpc(network, "eth_getTransactionCount", [dest, "latest"]),
    rpc(network, "eth_getBalance", [dest, "latest"]),
    transferLogs(network, dest, "from", latest),
    transferLogs(network, dest, "to", latest),
    me ? transferLogs(network, me, "from", latest) : Promise.resolve([]),
    me ? transferLogs(network, me, "to", latest) : Promise.resolve([])
  ]);
  const isContract = code !== "0x" && code !== "0x0";
  const nonce = parseInt(nonceHex, 16);
  const balanceWei = BigInt(balHex);
  const balanceBnb = (Number(balanceWei) / 1e18).toFixed(6);
  if (me && dest === me) {
    findings.push({ level: "orange", text: "The destination is your own wallet." });
  }
  if (isContract) {
    const isToken = Object.values(TOKENS[network]).some((a) => a.toLowerCase() === dest);
    findings.push({
      level: isToken ? "red" : "orange",
      text: isToken ? `The destination is the ${symbolOf(network, dest)} TOKEN CONTRACT itself \u2014 tokens sent there are lost forever.` : "The destination is a smart contract, not a personal wallet. Only send if you know exactly what this contract does."
    });
  } else if (nonce === 0 && balanceWei === 0n) {
    findings.push({
      level: "orange",
      text: "The destination has never sent a transaction and holds 0 BNB: it is brand new or unused. Double-check it with the recipient through another channel."
    });
  } else if (nonce === 0) {
    findings.push({
      level: "orange",
      text: "The destination has never sent a transaction itself (receive-only so far)."
    });
  } else {
    findings.push({
      level: "green",
      text: `The destination is an active wallet (${nonce} transactions sent).`
    });
  }
  const destLogs = [...destOut, ...destIn];
  const zeroish = destLogs.filter((l) => BigInt(l.data === "0x" ? 0 : l.data) < DUST);
  const zeroCounterparties = new Set(
    zeroish.map((l) => {
      const from = unpad(l.topics[1]);
      const to = unpad(l.topics[2]);
      return from === dest ? to : from;
    })
  );
  if (zeroCounterparties.size >= 5) {
    findings.push({
      level: "red",
      text: `The destination was involved in ${zeroish.length} zero-value or dust stablecoin transfers with ${zeroCounterparties.size} different wallets in the last ~${CHUNK * CHUNKS} blocks. That is the signature of an address-poisoning bot.`
    });
  } else if (zeroish.length > 0) {
    findings.push({
      level: "orange",
      text: `The destination appears in ${zeroish.length} zero-value or dust stablecoin transfer(s) recently. Legitimate wallets rarely do this.`
    });
  }
  if (me) {
    const real = /* @__PURE__ */ new Set();
    const zeroOnly = /* @__PURE__ */ new Set();
    for (const l of [...myOut, ...myIn]) {
      const from = unpad(l.topics[1]);
      const to = unpad(l.topics[2]);
      const other = from === me ? to : from;
      const value = BigInt(l.data === "0x" ? 0 : l.data);
      if (value >= DUST) real.add(other);
      else zeroOnly.add(other);
    }
    for (const r of real) zeroOnly.delete(r);
    if (real.has(dest)) {
      findings.push({
        level: "green",
        text: "You have already exchanged real stablecoin amounts with this exact address recently."
      });
    } else if (zeroOnly.has(dest)) {
      findings.push({
        level: "red",
        text: "This address only ever sent/received ZERO or dust amounts with your wallet. It was planted in your history: do NOT copy addresses from your transaction list."
      });
    }
    let best = null;
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
      findings.push({
        level: "orange",
        text: `Your history also contains a LOOKALIKE of this address (${best.addr}, first ${best.head} / last ${best.tail} characters identical). This one is the address you really paid, but someone is trying to poison your history: always copy it from a trusted source, never from your transaction list.`
      });
    } else if (best) {
      findings.push({
        level: "red",
        text: `LOOKALIKE: the destination shares its first ${best.head} and last ${best.tail} characters with ${best.addr}, an address from your recent history${real.has(best.addr) ? " that you really paid" : ""}. This is the classic address-poisoning trick; compare every character.`
      });
    }
    if (!real.has(dest) && !zeroOnly.has(dest) && !best) {
      findings.push({
        level: "green",
        text: "No lookalike of this address was found in your recent stablecoin history."
      });
    }
  }
  const verdict = findings.some((f) => f.level === "red") ? "red" : findings.some((f) => f.level === "orange") ? "orange" : "green";
  return {
    network,
    destination: dest,
    wallet: me,
    scannedBlocks: CHUNK * CHUNKS,
    destinationProfile: { isContract, nonce, balanceBnb },
    findings,
    lookalike,
    verdict
  };
}
var EMOJI = { green: "\u{1F7E2}", orange: "\u{1F7E0}", red: "\u{1F534}" };
function formatReport(r) {
  return [
    `${EMOJI[r.verdict]} phishcheck verdict: ${r.verdict.toUpperCase()}`,
    `Destination: ${r.destination} (${r.network})`,
    r.wallet ? `Your wallet: ${r.wallet}` : "Your wallet: not provided (lookalike check skipped)",
    "",
    ...r.findings.map((f) => `${EMOJI[f.level]} ${f.text}`),
    "",
    `Scanned the last ~${r.scannedBlocks} blocks of ${Object.keys(TOKENS[r.network]).join("/")} transfers.`
  ].join("\n");
}
export {
  analyze,
  formatReport,
  parseRequest
};
