const PERIOD_MS = {
  '1h': 3600000,
  '6h': 21600000,
  '24h': 86400000,
  '7d': 604800000,
  '30d': 2592000000,
};

function getSinceOptional(period) {
  const offset = PERIOD_MS[period];
  if (!offset) return null;
  return new Date(Date.now() - offset).toISOString();
}

function getSinceOrDefault(period, defaultPeriod = '24h') {
  return getSinceOptional(period) ?? getSinceOptional(defaultPeriod);
}

module.exports = { PERIOD_MS, getSinceOptional, getSinceOrDefault };
