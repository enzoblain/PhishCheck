# phishcheck

**Before you send crypto, phishcheck checks whether the address is an address-poisoning trap.**

phishcheck is a BNB Chain seller agent (ERC-8004 identity, paid per check through ERC-8183)
built with [BNB Agent Studio](https://docs.bnbchain.org/developer-kit/bnbchain-studio/).
Give it a destination address, optionally with your own wallet, and it returns a
🟢 / 🟠 / 🔴 verdict with plain-language reasons.

## What it detects

Address poisoning: an attacker generates an address that starts and ends like one of
your real contacts, then plants it in your history with zero-value or dust transfers.
You copy it from your transaction list, and the funds are gone.

phishcheck reads the chain (stablecoin transfers over the last ~135k blocks) and flags:

- **Lookalikes**: the destination shares its first and last characters with an address
  you actually paid.
- **Planted counterparties**: the destination only ever exchanged zero or dust amounts
  with your wallet.
- **Poisoning bots**: the destination does zero-value transfers with many wallets.
- **Risky destinations**: brand-new or empty addresses, smart contracts, and token
  contracts (funds sent there are lost).

The verdict is computed deterministically from on-chain data. The LLM only explains it.

## Layout

| Path | What it is |
| --- | --- |
| `app/agent/src/phishcheck.ts` | Analysis engine and the delivery hook (`phishcheckWork`) |
| `app/agent/src/dualMain.ts`, `mcpMain.ts` | Agent entrypoints (A2A + MCP), wired to `phishcheckWork` |
| `app/agent/studio.toml` | Network, wallet, LLM, price ($0.10 per check) |
| `web/` | **SafeSend**: a demo send UI that checks the address and asks for confirmation before signing |
| `.studio/` | Wallet keystore and secrets (git-ignored, never commit) |

## Run

```bash
bag doctor          # readiness checks
bag dev             # agent on :9000 (A2A card + /mcp)
pnpm web            # SafeSend demo on http://localhost:5173
```

In SafeSend, a 🟢 verdict sends directly. A 🟠 verdict requires confirming that you
verified the address through another channel. A 🔴 verdict requires retyping the last
6 characters of the address before you can send anyway.

## Deploy

```bash
bag deploy prepare --provider bnb
bag deploy --provider bnb          # 48h BNB testnet trial
bag deploy verify --provider bnb   # register / reconcile the ERC-8004 identity
```
