/**
 * WardSONDB custom `_id` helpers for the rollup collections.
 *
 * WardSONDB refuses a document id that is empty, `.`/`..`, or carries a path
 * separator (`/`, `\`) or a control character — `400 INVALID_DOCUMENT`, on a
 * path parameter (after percent-decoding, so `a%2Fb` is refused too) and on a
 * body `_id`, single or bulk. Inside `_bulk` that is a per-document error: the
 * rest of the batch lands and the offending document is silently gone.
 *
 * Rollup ids embed natural keys — IDS signature text, MACs, IPs, ports — so
 * every segment is escaped before it goes into an `_id`. `escapeIdSegment` is
 * the identity for clean input, which keeps the ids of keys that never carried
 * a forbidden character byte-identical to the pre-escape scheme. `%` is escaped
 * as well so the mapping stays injective: `a/b` and the literal `a%2Fb` get
 * different ids, so two distinct signatures can never collide on one delta.
 *
 * The escape is `%XX` of the UTF-16 code unit (every escaped character is
 * <= U+009F, so two hex digits always suffice). It is our own id scheme, not
 * URL encoding — `encodeURIComponent()` is still applied on top of it when an
 * id goes into a request path.
 */
const crypto = require('crypto');

// `%`, the two path separators, and U+0000–U+001F / U+007F–U+009F — the
// latter two ranges are Unicode category Cc, what Rust's `char::is_control`
// (WardSONDB's `segment_fault`) rejects.
const FORBIDDEN = /[%\/\\\u0000-\u001f\u007f-\u009f]/g;

/** WardSONDB's MAX_CUSTOM_ID_LENGTH, in bytes. */
const MAX_ID_BYTES = 512;

/**
 * Budget for the escaped natural-key part of an id. The bucket (20 bytes), two
 * separators and the longest suffix (a flushId, `${Date.now()}-${n}`, ~17
 * bytes) leave comfortable headroom under MAX_ID_BYTES.
 */
const MAX_KEY_BYTES = 440;

function escapeIdSegment(value) {
  return String(value ?? '').replace(FORBIDDEN, (c) =>
    '%' + c.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0'));
}

/**
 * Build a rollup document `_id`: `${bucket}|${key segments…}|${suffix}`.
 * `suffix` is the flushId for a delta document or `'c'` for a canonical one.
 * An over-long key part collapses to `#` + sha256 hex of the escaped key; the
 * threshold is on the key part alone so the delta and canonical forms of one
 * key always agree.
 */
function rollupId(bucket, keySegments, suffix) {
  let keyPart = keySegments.map(escapeIdSegment).join('|');
  if (Buffer.byteLength(keyPart, 'utf8') > MAX_KEY_BYTES) {
    keyPart = '#' + crypto.createHash('sha256').update(keyPart).digest('hex');
  }
  return `${escapeIdSegment(bucket)}|${keyPart}|${suffix}`;
}

module.exports = { escapeIdSegment, rollupId, MAX_ID_BYTES, MAX_KEY_BYTES };
