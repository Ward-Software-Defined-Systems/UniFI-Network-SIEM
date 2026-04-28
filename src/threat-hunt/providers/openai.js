const config = require('../../config');
const { parseSSEStream } = require('../../utils/sse');
const { throwSanitizedProviderError } = require('./util');

async function invoke(prompt, key) {
  const res = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${key}`,
    },
    body: JSON.stringify({
      model: config.threathunt.openaiModel,
      max_tokens: config.threathunt.openaiMaxTokens,
      messages: [{ role: 'user', content: prompt }],
    }),
  });

  if (!res.ok) await throwSanitizedProviderError('OpenAI', res);

  const data = await res.json();
  return data.choices?.[0]?.message?.content || 'No response from OpenAI';
}

async function stream(prompt, key, sendEvent, signal) {
  const res = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${key}`,
    },
    body: JSON.stringify({
      model: config.threathunt.openaiModel,
      max_tokens: config.threathunt.openaiMaxTokens,
      stream: true,
      messages: [{ role: 'user', content: prompt }],
    }),
    signal,
  });

  if (!res.ok) await throwSanitizedProviderError('OpenAI', res);

  for await (const { data } of parseSSEStream(res.body)) {
    if (data === '[DONE]') break;
    if (!data || typeof data !== 'object') continue;
    const text = data.choices?.[0]?.delta?.content;
    if (text) sendEvent('chunk', { text });
  }
}

module.exports = { invoke, stream };
