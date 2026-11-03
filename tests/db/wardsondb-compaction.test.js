// Compaction and reset behaviour of the WardSONDB backend against a stubbed
// server. No network — `_post` / `_put` / `_get` / `_delete` are replaced per
// test, same pattern as wardsondb-cursor.test.js.

const WardsonDbBackend = require('../../src/db/backends/wardsondb');
const { rollupId } = require('../../src/db/backends/wardsondb-ids');

function newBackend() {
  return new WardsonDbBackend({ host: 'localhost', port: 8080 });
}

const BUCKET = '2026-11-02T18:00:00Z';
const CUTOFF = '2026-11-02T19:30:00Z';
const SIG = 'ET WEB_SERVER /etc/passwd Detected in URI';
const CLS = 'Web Application Attack';
const NEW_CANONICAL_ID = rollupId(BUCKET, [SIG, CLS], 'c');
const OLD_CANONICAL_ID = `${BUCKET}|${SIG}|${CLS}|c`; // pre-escape scheme, raw slashes

function sigDelta(flushId, count) {
  return { _id: rollupId(BUCKET, [SIG, CLS], flushId), bucket: BUCKET, signature: SIG, classification: CLS, count, delta: true };
}

function project(doc, fields) {
  if (!fields) return doc;
  const out = {};
  for (const f of fields) if (f in doc) out[f] = doc[f];
  return out;
}

/** Stub one sig-hourly bucket. `canonicalReadFails` makes the canonical page read throw. */
function stubServer(b, { deltas, canonicals, canonicalReadFails = false }) {
  const calls = { puts: [], deletes: [] };
  b._put = async (path, doc) => { calls.puts.push({ path, doc }); return { ok: true, data: doc }; };
  b._post = async (path, body) => {
    if (path.endsWith('/distinct')) return { ok: true, data: { values: [BUCKET] } };
    if (path.endsWith('/query')) {
      const f = body.filter || {};
      if (f.delta === false && canonicalReadFails) throw new Error('WardSONDB QUERY_TIMEOUT: boom');
      const rows = f.delta === true ? deltas : f.delta === false ? canonicals : [];
      const offset = body.offset || 0;
      const page = rows.slice(offset, offset + (body.limit || 1000));
      return { ok: true, data: page.map((d) => project(d, body.fields)) };
    }
    if (path.endsWith('/aggregate')) {
      const wanted = new Set(body.pipeline[0].$match._id.$in);
      const sum = deltas.filter((d) => wanted.has(d._id)).reduce((n, d) => n + d.count, 0);
      return { ok: true, data: sum ? [{ _id: { signature: SIG, classification: CLS }, count: sum }] : [] };
    }
    if (path.endsWith('/_delete_by_query')) {
      calls.deletes.push(body.filter._id.$in);
      return { ok: true, data: { deleted: body.filter._id.$in.length } };
    }
    throw new Error(`unexpected POST ${path}`);
  };
  return calls;
}

describe('WardSONDB rollup compaction', () => {
  const b = newBackend();
  const spec = b._compactionSpecs().find((s) => s.col === b.rollupSigHourly);

  it('folds claimed deltas into an escaped canonical and removes the canonical left under the old slash id', async () => {
    const deltas = [sigDelta('1762140000000-1', 2), sigDelta('1762140005000-2', 3)];
    const canonicals = [{ _id: OLD_CANONICAL_ID, bucket: BUCKET, signature: SIG, classification: CLS, count: 10, delta: false }];
    const calls = stubServer(b, { deltas, canonicals });

    const result = await b._compactCollection(spec, CUTOFF);

    expect(result).toEqual({ canonicals: 1, deltas: 2 });
    expect(calls.puts).toHaveLength(1);
    expect(calls.puts[0].path).toBe(`/rollups-sig-hourly/docs/${encodeURIComponent(NEW_CANONICAL_ID)}`);
    expect(NEW_CANONICAL_ID).toBe(`${BUCKET}|ET WEB_SERVER %2Fetc%2Fpasswd Detected in URI|${CLS}|c`);
    expect(calls.puts[0].doc).toEqual({ bucket: BUCKET, signature: SIG, classification: CLS, delta: false, count: 15 });

    // First the claimed deltas, then the superseded canonical — never the new one.
    expect(calls.deletes).toEqual([deltas.map((d) => d._id), [OLD_CANONICAL_ID]]);
    expect(calls.deletes.flat()).not.toContain(NEW_CANONICAL_ID);
  });

  it('leaves a canonical that already carries the current id alone', async () => {
    const deltas = [sigDelta('1762140000000-1', 4)];
    const canonicals = [{ _id: NEW_CANONICAL_ID, bucket: BUCKET, signature: SIG, classification: CLS, count: 10, delta: false }];
    const calls = stubServer(b, { deltas, canonicals });

    const result = await b._compactCollection(spec, CUTOFF);

    expect(result).toEqual({ canonicals: 1, deltas: 1 });
    expect(calls.puts).toHaveLength(1);
    expect(calls.puts[0].doc.count).toBe(14);
    expect(calls.deletes).toEqual([deltas.map((d) => d._id)]);
  });

  it('writes and deletes nothing for the bucket when the canonical read fails (strict paging)', async () => {
    const deltas = [sigDelta('1762140000000-1', 4)];
    const canonicals = [{ _id: OLD_CANONICAL_ID, bucket: BUCKET, signature: SIG, classification: CLS, count: 10, delta: false }];
    const calls = stubServer(b, { deltas, canonicals, canonicalReadFails: true });

    const result = await b._compactCollection(spec, CUTOFF);

    expect(result).toEqual({ canonicals: 0, deltas: 0 });
    expect(calls.puts).toHaveLength(0);
    expect(calls.deletes).toHaveLength(0);
  });

  it('claims deltas across pages and tolerates a failed delta page', async () => {
    const many = Array.from({ length: 1500 }, (_, i) => sigDelta(`1762140000000-${i}`, 1));
    const canonicals = [];
    stubServer(b, { deltas: many, canonicals });
    const ids = await b._snapshotDeltaIds(b.rollupSigHourly, BUCKET);
    expect(ids).toHaveLength(1500);
    expect(new Set(ids).size).toBe(1500);

    let pages = 0;
    const post = b._post;
    b._post = async (path, body) => {
      if (path.endsWith('/query') && ++pages === 2) throw new Error('WardSONDB QUERY_TIMEOUT: boom');
      return post(path, body);
    };
    const partial = await b._snapshotDeltaIds(b.rollupSigHourly, BUCKET);
    expect(partial).toHaveLength(1000);
  });
});

describe('WardSONDB resetData', () => {
  it('re-installs the rollup TTL policies after recreating the collections', async () => {
    const b = newBackend();
    b._get = async () => ({ ok: true, data: [] });
    b._delete = async () => ({ ok: true });
    b._post = async () => ({ ok: true });
    b._ensurePartition = async () => {};
    const created = [];
    b._ensureCollection = async (name) => { created.push(name); };
    b._startFlushInterval = () => {};
    b._setRollupTTLs = vi.fn(async () => {});

    await b.resetData();

    expect(b._setRollupTTLs).toHaveBeenCalledTimes(1);
    // The policies are installed after the rollup collections exist again.
    expect(created).toEqual(expect.arrayContaining([b.rollup5m, b.rollupSigHourly, b.cacheCollection]));
    expect(b._cachedDocCount).toBe(0);
  });
});
