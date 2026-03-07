const express = require('express');
const { queryEvents, getEventById } = require('../../db/events');

const router = express.Router();

router.get('/', (req, res) => {
  try {
    const events = queryEvents(req.query);
    res.json(events);
  } catch (err) {
    res.status(500).json({ error: 'Failed to query events' });
  }
});

router.get('/:id', (req, res) => {
  try {
    const event = getEventById(parseInt(req.params.id, 10));
    if (!event) return res.status(404).json({ error: 'Event not found' });
    res.json(event);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get event' });
  }
});

module.exports = router;
