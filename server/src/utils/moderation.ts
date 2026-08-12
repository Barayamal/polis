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
const IP_LOOKUP_TIMEOUT_MS = 5_000;

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

loadFiles();

export async function getRegionFromIP(ip: string): Promise<string> {
  if (!ip) {
    return DEFAULT_REGION;
  }
  try {
    const response = await fetch(
      `http://ip-api.com/json/${encodeURIComponent(ip)}`,
      {
        redirect: "follow",
        signal: AbortSignal.timeout(IP_LOOKUP_TIMEOUT_MS),
      }
    );
    if (!response.ok) {
      throw new Error(`IP lookup returned HTTP ${response.status}.`);
    }
    const data = JSON.parse(await response.text()) as {
      status?: string;
      city?: string;
      regionName?: string;
      country?: string;
    };
    if (data.status === "success" && data.country) {
      return [data.city, data.regionName, data.country]
        .filter(Boolean)
        .join(", ");
    }
  } catch (error) {
    logger.error("Error fetching region from IP:", { error });
  }
  return DEFAULT_REGION;
}

async function analyzeComment(
  txt: string,
  convo_topic: string,
  geographical_context?: string // ip address if available
) {
  try {
    const json = await convertXML(internal_config.fileContents);
    const finalGeographicalContext = geographical_context
      ? await getRegionFromIP(geographical_context)
      : DEFAULT_REGION;
    json.polis_moderation_rubric.children[11].task.children[1].input = {
      comment_text: txt,
      conversation_topic: convo_topic,
      geographical_context: finalGeographicalContext,
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
    logger.debug(`${txt} moderation result: ${result}`);
    return JSON.parse(result).output?.final_score;
  } catch (error) {
    return;
  }
}

export default analyzeComment;
