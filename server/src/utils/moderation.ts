import { GoogleGenAI } from "@google/genai";
import config from "../config";
import { convertXML } from "simple-xml-to-json";
import logger from "./logger";
import fs from "fs/promises";

const js2xmlparser = require("js2xmlparser");

const internal_config = {
  fileContents: "",
  system_lore: "",
};
const DEFAULT_REGION = "US or Europe (EU)";
let promptLoadFailed = false;

async function loadFiles() {
  internal_config.fileContents = await fs.readFile(
    "src/prompts/moderation/script.xml",
    "utf8"
  );
  internal_config.system_lore = await fs.readFile(
    "src/prompts/report_experimental/system.xml",
    "utf8"
  );
}

// The fresh fixed-seed bootstrap has no moderation or geolocation role. The
// owned child starts from a fixed compiled directory, not an asset directory;
// importing this module must not read prompts or dispatch external work there.
export const moderationReady = config.freshBootstrapLocalOnly
  ? Promise.resolve()
  : loadFiles().catch(() => {
      // Handle rejection immediately, including when no caller starts an
      // analysis. Preserve Promise<void>; keep no raw filesystem exception.
      promptLoadFailed = true;
    });

// Backport the upstream 80193c65 privacy boundary: location stays at its
// existing fallback, never inferred from or enriched with a participant IP.
async function analyzeComment(txt: string, convo_topic: string) {
  if (config.freshBootstrapLocalOnly)
    throw new Error("FNCP_FRESH_BOOTSTRAP_MODERATION_DISABLED");
  try {
    await moderationReady;
    if (promptLoadFailed)
      throw new Error("POLIS_MODERATION_PROMPTS_UNAVAILABLE");
    const json = await convertXML(internal_config.fileContents);
    json.polis_moderation_rubric.children[11].task.children[1].input = {
      comment_text: txt,
      conversation_topic: convo_topic,
      geographical_context: DEFAULT_REGION,
    };

    const prompt_xml = js2xmlparser.parse("polis_moderation_rubric", json);

    const genAI = new GoogleGenAI({ apiKey: config.geminiApiKey });
    const respGem = await genAI.models.generateContent({
      model: "gemini-2.5-pro",
      config: {
        responseMimeType: "application/json",
        maxOutputTokens: 50000,
      },
      contents: [
        {
          parts: [
            {
              text: `
                  ${internal_config.system_lore}
  
                  ${prompt_xml}
  
                  You MUST respond with score object ONLY. Nothing else is permitted. The response structure should be as follows:
                  {
                    "output": {
                      "base_score": "NUMBER",
                      "substance_level": "STRING",
                      "multiplier": "N/A | NUMBER",
                      "final_score": "NUMBER",
                      "decision": "STRING"
                    }
                  }
                  KEEP THE EXACT STRUCTURE.
                `,
            },
          ],
          role: "user",
        },
      ],
    });

    const result = respGem.text;
    const rawScore = JSON.parse(result).output?.final_score;
    // The prompt historically returns both JSON numbers and number strings.
    // Normalize only JSON-style numeric text, never null/booleans/arrays or
    // empty/hexadecimal strings through Number's broader coercion rules.
    const score =
      typeof rawScore === "number"
        ? rawScore
        : typeof rawScore === "string" &&
          /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$/u.test(rawScore.trim())
        ? Number(rawScore.trim())
        : NaN;
    if (!Number.isFinite(score) || score < 0)
      throw new Error("POLIS_MODERATION_SCORE_UNAVAILABLE");
    logger.debug("polis_moderation_analysis_completed");
    return score;
  } catch {
    // SDK/parser errors may contain the prompt, address or model response.
    logger.error("polis_moderation_analysis_unavailable");
    return;
  }
}

export default analyzeComment;
