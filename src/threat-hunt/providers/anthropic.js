const config = require('../../config');
const { parseSSEStream } = require('../../utils/sse');

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
      messages: [{ role: 'user', content: prompt }],
    }),
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Anthropic API error ${res.status}: ${err}`);
  }

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
      stream: true,
      messages: [{ role: 'user', content: prompt }],
    }),
    signal,
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Anthropic API error ${res.status}: ${err}`);
  }

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
