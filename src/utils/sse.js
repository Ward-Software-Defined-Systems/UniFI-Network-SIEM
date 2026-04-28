/**
 * Server-Sent Events helpers.
 *
 * parseSSEStream consumes a fetch ReadableStream body and yields
 * { event, data } pairs as they arrive. The eventType state lives
 * outside the for-await loop so an `event:` line whose matching
 * `data:` line lands in the next chunk still pairs correctly.
 */
async function* parseSSEStream(body) {
  const decoder = new TextDecoder();
  let buffer = '';
  let eventType = null;
  for await (const chunk of body) {
    buffer += decoder.decode(chunk, { stream: true });
    const lines = buffer.split('\n');
    buffer = lines.pop(); // keep incomplete line in buffer
    for (const line of lines) {
      if (line.startsWith('event: ')) {
        eventType = line.slice(7).trim();
      } else if (line.startsWith('data: ')) {
        const data = line.slice(6);
        try {
          yield { event: eventType, data: JSON.parse(data) };
        } catch {
          yield { event: eventType, data };
        }
        eventType = null;
      }
    }
  }
}

module.exports = { parseSSEStream };
