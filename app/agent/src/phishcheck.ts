import { generateText, type LanguageModel } from "ai";
import { analyze, formatReport, parseRequest, type Report } from "./phishcheckCore.js";

export * from "./phishcheckCore.js";

// ── Delivery hook ─────────────────────────────────────────────────────────────

const USAGE =
  "phishcheck needs at least one BSC address.\n" +
  "Send: `<destination address> [your wallet address] [testnet]`\n" +
  "Example: `Check 0xDEST... before I send from my wallet 0xMINE...`";

/**
 * The work this agent sells: facts come from `analyze` (deterministic RPC
 * reads), the LLM only explains them. If the LLM fails, the raw report is
 * still delivered so a paid job never ends without a deliverable.
 */
export async function phishcheckWork(
  prompt: string,
  getModel: () => LanguageModel,
  abortSignal?: AbortSignal,
): Promise<string> {
  const { destination, wallet, network } = parseRequest(prompt);
  if (!destination) return USAGE;

  const report = await analyze(destination, wallet, network);
  const raw = formatReport(report);
  const explained = await explainReport(report, prompt, getModel, abortSignal);
  return explained ? `${explained}\n\n---\nRaw report:\n${raw}` : raw;
}

/**
 * Plain-language explanation of a report by the LLM, in the language of
 * `userText`. Returns null when the LLM fails (callers fall back to the
 * deterministic report).
 */
export async function explainReport(
  report: Report,
  userText: string,
  getModel: () => LanguageModel,
  abortSignal?: AbortSignal,
): Promise<string | null> {
  try {
    const { text } = await generateText({
      model: getModel(),
      system:
        "You are phishcheck, a security assistant that protects people from address " +
        "poisoning and phishing before they send crypto on BNB Chain. You receive a " +
        "FACTUAL report computed from on-chain data. Explain it to a non-expert in the " +
        "same language as the user's request (default English). Start with the verdict " +
        "emoji and one-line recommendation (send / double-check / do NOT send), then the " +
        "key reasons as short bullets, then one concrete safety tip. Never invent facts " +
        "that are not in the report (e.g. do not claim how many characters differ), " +
        "never change the verdict, max 150 words. " +
        "Output ONLY the final message wrapped in <answer></answer> tags, no reasoning.",
      prompt: `User request:\n${userText}\n\nReport (JSON):\n${JSON.stringify(report, null, 2)}`,
      abortSignal,
    });
    return extractAnswer(text);
  } catch (err) {
    console.error("[phishcheck] LLM explanation failed, using raw report:", (err as Error).message);
    return null;
  }
}

/** Keep only the final answer; free models sometimes leak their reasoning. */
function extractAnswer(text: string): string | null {
  const final = text.split(/<\/think>/i).pop()!;
  const open = final.lastIndexOf("<answer>");
  if (open !== -1) {
    const body = final.slice(open + "<answer>".length).split(/<\/answer>/i)[0]!.trim();
    if (body) return body;
  }
  const plain = final.trim();
  // Accept untagged text only if it starts with the verdict emoji.
  return /^(🟢|🟠|🔴)/u.test(plain) ? plain : null;
}
