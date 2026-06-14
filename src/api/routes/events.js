const express = require('express');
const storage = require('../../db/storage');

const router = express.Router();

router.get('/', async (req, res) => {
  try {
    const backend = storage.getBackend();
    const result = await backend.queryEvents(req.query);
    // M4: response shape is now `{events, hasMore, nextCursor}` for
    // backends that support keyset pagination (currently WardSONDB).
    // Frontend code that treats the body as just an array still works
    // because `result.events` is always present and matches the legacy
    // shape — but the new fields let pagination-aware UIs skip
    // straight to the next page without offset math.
    res.json({
      events: result.events,
      hasMore: result.hasMore ?? false,
      nextCursor: result.nextCursor ?? null,
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to query events' });
  }
});

router.get('/:id', async (req, res) => {
  try {
    const backend = storage.getBackend();
    const event = await backend.getEventById(req.params.id);
    if (!event) return res.status(404).json({ error: 'Event not found' });
    res.json(event);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get event' });
  }
});

module.exports = router;
