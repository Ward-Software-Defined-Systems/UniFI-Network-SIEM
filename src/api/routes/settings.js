const express = require('express');
const { getDb, resetDb } = require('../../db/database');
const config = require('../../config');

const router = express.Router();

router.get('/', (req, res) => {
  try {
    const db = getDb();
    const rows = db.prepare('SELECT key, value FROM settings').all();
    const settings = {};
    for (const row of rows) {
      try { settings[row.key] = JSON.parse(row.value); } catch { settings[row.key] = row.value; }
    }
    // Redact sensitive keys — only indicate presence
    if (settings.abuseIpDbKey) {
      settings.abuseIpDbKey = '••••••••' + settings.abuseIpDbKey.slice(-4);
    }
    res.json(settings);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get settings' });
  }
});

router.put('/', (req, res) => {
  try {
    const db = getDb();
    const upsert = db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)');
    const txn = db.transaction((entries) => {
      for (const [key, value] of entries) {
        upsert.run(key, JSON.stringify(value));
      }
    });
    txn(Object.entries(req.body));

    // Update in-memory config for keys that take effect immediately
    if (req.body.abuseIpDbKey !== undefined) {
      config.enrichment.abuseIpDbKey = req.body.abuseIpDbKey;
    }
    if (req.body.rdnsEnabled !== undefined) {
      config.enrichment.rdnsEnabled = !!req.body.rdnsEnabled;
    }

    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save settings' });
  }
});

router.post('/reset-db', (req, res) => {
  try {
    resetDb();
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to reset database' });
  }
});

module.exports = router;
