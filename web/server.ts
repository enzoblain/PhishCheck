/**
 * SafeSend demo front for phishcheck.
 *
 * Serves web/index.html and a small local JSON API backed by the same
 * analysis engine the paid agent sells (app/agent/src/phishcheck.ts):
 *   POST /api/check   {destination, wallet?, network}  -> Report
 *   POST /api/explain {report, lang}                    -> {text|null}
 *
 * The browser wallet (MetaMask, Rabby…) signs and sends the transfer; this
 * server never touches any key. Run from the workspace root: `pnpm web`.
 */

import { readFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  analyze,
  explainReport,
  type Network,
  type Report,
} from "../app/agent/src/phishcheck.ts";
import { buildModel } from "../app/agent/src/model.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT ?? 5173);
const ADDR = /^0x[0-9a-fA-F]{40}$/;
const NETWORKS: Network[] = ["bsc-mainnet", "bsc-testnet"];

let model: ReturnType<typeof buildModel> | undefined;
const getModel = () => (model ??= buildModel());

async function body(req: IncomingMessage): Promise<Record<string, unknown>> {
  let raw = "";
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > 100_000) throw new Error("body too large");
  }
  return raw ? (JSON.parse(raw) as Record<string, unknown>) : {};
}

function json(res: ServerResponse, status: number, data: unknown) {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(data));
}

const server = createServer(async (req, res) => {
  try {
    if (req.method === "GET" && (req.url === "/" || req.url === "/index.html")) {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(await readFile(join(HERE, "index.html")));
      return;
    }

    if (req.method === "POST" && req.url === "/api/check") {
      const b = await body(req);
      const destination = String(b.destination ?? "");
      const wallet = b.wallet ? String(b.wallet) : null;
      const network = String(b.network ?? "bsc-mainnet") as Network;
      if (!ADDR.test(destination)) return json(res, 400, { error: "Adresse de destination invalide." });
      if (wallet && !ADDR.test(wallet)) return json(res, 400, { error: "Adresse du wallet invalide." });
      if (!NETWORKS.includes(network)) return json(res, 400, { error: "Réseau inconnu." });
      return json(res, 200, await analyze(destination, wallet, network));
    }

    if (req.method === "POST" && req.url === "/api/explain") {
      const b = await body(req);
      const report = b.report as Report | undefined;
      if (!report?.findings) return json(res, 400, { error: "report manquant" });
      const lang = b.lang === "en" ? "English" : "French";
      const text = await explainReport(
        report,
        `(Answer in ${lang}.) I am about to send funds to ${report.destination}. Is it safe?`,
        getModel,
        AbortSignal.timeout(60_000),
      );
      return json(res, 200, { text });
    }

    json(res, 404, { error: "not found" });
  } catch (err) {
    console.error("[safesend]", err);
    json(res, 500, { error: (err as Error).message });
  }
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`SafeSend (phishcheck) → http://localhost:${PORT}`);
});
