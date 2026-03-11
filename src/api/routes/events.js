const express = require('express');
const storage = require('../../db/storage');

const router = express.Router();

router.get('/', async (req, res) => {
  try {
    const backend = storage.getBackend();
    const result = await backend.queryEvents(req.query);
    res.json(result.events);
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
