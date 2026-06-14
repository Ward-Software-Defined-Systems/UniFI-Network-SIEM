const config = require('../../config');
const { parseSSEStream } = require('../../utils/sse');
const { throwSanitizedProviderError } = require('./util');
const { buildSystemPrompt } = require('../prompt');

// H2: pass the threat-hunt system prompt as Anthropic's `system`
// parameter rather than mixing it into the user message. Anthropic
// gives system messages elevated trust over user content — keeping
// the "treat <untrusted> as data" instruction here means the model
// is less likely to be talked out of it by hostile content in the
// user prompt body.
function huntSystemPrompt() {
  return buildSystemPrompt();
}

async function invoke(prompt, key) {
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': key,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: config.threathunt.anthropicModel,
      max_tokens: config.threathunt.anthropicMaxTokens,
      thinking: { type: 'adaptive', display: 'summarized' },
      // Deepest reasoning setting for the most thorough analysis (GA; default 'high').
      output_config: { effort: 'max' },
      system: huntSystemPrompt(),
      messages: [{ role: 'user', content: prompt }],
    }),
  });

  if (!res.ok) await throwSanitizedProviderError('Anthropic', res);

  const data = await res.json();
  // With thinking enabled, find the text content block (skip thinking blocks)
  const textBlock = data.content?.find((b) => b.type === 'text');
  return textBlock?.text || 'No response from Anthropic';
}

async function stream(prompt, key, sendEvent, signal) {
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': key,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: config.threathunt.anthropicModel,
      max_tokens: config.threathunt.anthropicMaxTokens,
      thinking: { type: 'adaptive', display: 'summarized' },
      // Deepest reasoning setting for the most thorough analysis (GA; default 'high').
      output_config: { effort: 'max' },
      system: huntSystemPrompt(),
      stream: true,
      messages: [{ role: 'user', content: prompt }],
    }),
    signal,
  });

  if (!res.ok) await throwSanitizedProviderError('Anthropic', res);

  for await (const { data } of parseSSEStream(res.body)) {
    if (!data || typeof data !== 'object') continue;

    if (data.type === 'content_block_start') {
      if (data.content_block?.type === 'thinking') {
        sendEvent('thinking_start', {});
      } else if (data.content_block?.type === 'text') {
        sendEvent('text_start', {});
      }
    } else if (data.type === 'content_block_delta') {
      if (data.delta?.type === 'thinking_delta') {
        sendEvent('thinking', { text: data.delta.thinking });
      } else if (data.delta?.type === 'text_delta') {
        sendEvent('chunk', { text: data.delta.text });
      }
      // skip signature_delta — not needed for single-turn
    }
  }
}

module.exports = { invoke, stream };
