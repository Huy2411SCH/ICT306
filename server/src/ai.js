// AI-assisted password feedback via the Google Gemini API.
// Privacy by design: the model receives ONLY derived statistics (length, character classes,
// pattern types, crack-time estimate), never the password or any substring of it.
import { GoogleGenAI } from '@google/genai';
import { config } from './config.js';

function createClient() {
  if (!config.aiFeedback) return null;
  if (!config.geminiApiKey || !config.geminiModel) {
    console.warn('AI_FEEDBACK=on but GEMINI_API_KEY or GEMINI_MODEL is missing; using rule-based feedback.');
    return null;
  }
  return new GoogleGenAI({ apiKey: config.geminiApiKey, httpOptions: { timeout: 20_000 } });
}

const client = createClient();

const SYSTEM_PROMPT = `You are a password-security coach inside a password manager.
You receive statistics describing a password, never the password itself.
Explain in plain English why it is weak or strong and give 2-4 short, specific, actionable tips.
Follow NIST SP 800-63B: favour length and passphrases over forced complexity, never reuse passwords.
Reply as plain-text bullet points starting with "- ". No preamble, no headings.`;

/** Returns an array of tips, or null if AI is disabled/unavailable (caller falls back to local rules). */
export async function aiFeedback(features, breaches) {
  if (!client) return null;
  try {
    const response = await client.models.generateContent({
      model: config.geminiModel,
      contents: JSON.stringify({ ...features, timesSeenInBreaches: breaches }),
      config: {
        systemInstruction: SYSTEM_PROMPT,
        maxOutputTokens: 2048, // headroom: on "thinking" models, reasoning tokens count toward this limit
        temperature: 0.3,
      },
    });
    if (response.promptFeedback?.blockReason) return null; // request blocked by safety filters
    const tips = (response.text ?? '')
      .split('\n')
      .map((line) => line.replace(/^\s*[-*•]\s*/, '').replace(/\*\*/g, '').trim())
      .filter(Boolean);
    return tips.length ? tips : null;
  } catch (err) {
    console.error('AI feedback unavailable:', err.message);
    return null;
  }
}
