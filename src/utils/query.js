/**
 * Query-string hygiene for routes that forward `req.query` into a storage
 * backend.
 *
 * Express 4's default "extended" parser (qs) turns `?src_ip[$ne]=x` into a
 * nested object and `?a=1&a=2` into an array. WardSONDB filters are built
 * from `$`-operator objects, so a bracketed key would become a real filter
 * operator; SQLite and OpenSearch fail with a 500 instead. The server uses
 * Express's 'simple' parser (no nesting) as the first layer; this helper is
 * the second: it keeps only own, string-valued entries and drops anything
 * that could reach a backend as an object, an array, or a prototype key.
 */

const BLOCKED_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function flatStringParams(query) {
  const out = {};
  if (!query || typeof query !== 'object') return out;
  for (const key of Object.keys(query)) {
    if (BLOCKED_KEYS.has(key)) continue;
    const value = query[key];
    if (typeof value === 'string') out[key] = value;
  }
  return out;
}

module.exports = { flatStringParams };
