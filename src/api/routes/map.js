const express = require('express');
const config = require('../../config');
const { resolveMapConfig } = require('../../map/providers');

const router = express.Router();

/**
 * GET /api/map/config — the Live Map's basemap, resolved from the live
 * `map.*` settings (no restart needed). This is the only route that returns
 * the CARTO key, and only substituted into the tile URL the browser must
 * request anyway; /api/settings/v2 keeps masking it. Never log the result.
 */
router.get('/config', (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json(resolveMapConfig(config));
});

module.exports = router;
