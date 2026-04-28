const config = require('../../config');
const { parseSSEStream } = require('../../utils/sse');
const { throwSanitizedProviderError } = require('./util');
const { buildSystemPrompt } = require('../prompt');

// H2: Gemini's `systemInstruction` field is the equivalent of
// Anthropic/OpenAI's system message — it carries elevated trust over
// the user contents.
function huntSystemInstruction() {
  return { parts: [{ text: buildSystemPrompt() }] };
}

async function invoke(prompt, key) {
  const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${config.threathunt.geminiModel}:generateContent?key=${key}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      systemInstruction: huntSystemInstruction(),
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: { maxOutputTokens: config.threathunt.geminiMaxTokens },
    }),
  });

  if (!res.ok) await throwSanitizedProviderError('Gemini', res);

  const data = await res.json();
  return data.candidates?.[0]?.content?.parts?.[0]?.text || 'No response from Gemini';
}

async function stream(prompt, key, sendEvent, signal) {
  const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${config.threathunt.geminiModel}:streamGenerateContent?alt=sse&key=${key}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      systemInstruction: huntSystemInstruction(),
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: { maxOutputTokens: config.threathunt.geminiMaxTokens },
    }),
    signal,
  });

  if (!res.ok) await throwSanitizedProviderError('Gemini', res);

  for await (const { data } of parseSSEStream(res.body)) {
    if (!data || typeof data !== 'object') continue;
    const text = data.candidates?.[0]?.content?.parts?.[0]?.text;
    if (text) sendEvent('chunk', { text });
  }
}

module.exports = { invoke, stream };
