const dns = require('dns');
const config = require('../config');

function reverseLookup(ip) {
  if (!config.enrichment.rdnsEnabled) return Promise.resolve(null);

  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(null), config.enrichment.rdnsTimeoutMs);

    dns.reverse(ip, (err, hostnames) => {
      clearTimeout(timer);
      if (err || !hostnames || hostnames.length === 0) {
        resolve(null);
      } else {
        resolve(hostnames[0]);
      }
    });
  });
}

module.exports = { reverseLookup };
