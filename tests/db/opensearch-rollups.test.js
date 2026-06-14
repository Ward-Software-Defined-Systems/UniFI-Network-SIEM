// Pure-data tests for the OpenSearch rollup-job definitions.
// These don't talk to OpenSearch — they verify the static job specs
// match the documented IM-plugin schema (so I don't ship a typo'd
// `interval` instead of `fixed_interval`, or a wrong `unit` casing).

const { buildRollupJobs } = require('../../src/db/backends/opensearch');

describe('buildRollupJobs', () => {
  const PREFIX = 'siem-';
  const jobs = buildRollupJobs(PREFIX);

  it('returns five jobs', () => {
    expect(jobs).toHaveLength(5);
  });

  it('each job has a stable id under the prefix', () => {
    const ids = jobs.map((j) => j.id);
    expect(ids).toEqual([
      'siem-rollup-5m',
      'siem-rollup-ip-hourly',
      'siem-rollup-port-hourly',
      'siem-rollup-sig-hourly',
      'siem-rollup-client-hourly',
    ]);
  });

  it('every job points at the events source index for the prefix', () => {
    for (const j of jobs) {
      expect(j.body.rollup.source_index).toBe('siem-events');
    }
  });

  it('target indexes are unique per job and live under the prefix', () => {
    const targets = jobs.map((j) => j.body.rollup.target_index);
    expect(new Set(targets).size).toBe(targets.length);
    for (const t of targets) {
      expect(t.startsWith(PREFIX)).toBe(true);
    }
  });

  it('every job is enabled and continuous', () => {
    for (const j of jobs) {
      expect(j.body.rollup.enabled).toBe(true);
      expect(j.body.rollup.continuous).toBe(true);
    }
  });

  it('schedule uses interval shape with title-cased unit', () => {
    for (const j of jobs) {
      const sched = j.body.rollup.schedule;
      expect(sched).toHaveProperty('interval');
      expect(typeof sched.interval.period).toBe('number');
      expect(sched.interval.period).toBeGreaterThan(0);
      // OpenSearch IM plugin requires title-case unit strings — Minutes/Hours/Days.
      expect(['Minutes', 'Hours', 'Days']).toContain(sched.interval.unit);
    }
  });

  it('every dimension uses fixed_interval (not interval) for date_histogram', () => {
    for (const j of jobs) {
      for (const d of j.body.rollup.dimensions) {
        if (d.date_histogram) {
          expect(d.date_histogram).toHaveProperty('fixed_interval');
          expect(d.date_histogram).not.toHaveProperty('interval');
          expect(d.date_histogram.source_field).toBe('received_at');
        }
      }
    }
  });

  it('terms dimensions reference fields that exist in the FLAT events mapping', () => {
    // These are the actual indexed fields from EVENTS_MAPPING (flat
    // names — `network_action`, NOT `network.action`). Any new rollup
    // term source_field must be added here AND verified to exist in
    // the events index mapping, otherwise the IM plugin happily
    // creates the job and silently rolls up nothing.
    const validFields = new Set([
      'event_type', 'network_action', 'src_ip', 'dst_ip', 'direction',
      'dst_port', 'protocol', 'ids_signature', 'ids_category',
      // mac_address is the canonical first-non-null mac set at ingest; the
      // three raw mac fields still exist in the mapping but are no longer
      // rolled up directly (see client-hourly).
      'mac_address', 'client_mac', 'wifi_client_mac', 'dhcp_mac',
    ]);
    for (const j of jobs) {
      for (const d of j.body.rollup.dimensions) {
        if (d.terms) {
          expect(validFields.has(d.terms.source_field)).toBe(true);
        }
      }
    }
  });

  it('every job declares value_count metric on received_at', () => {
    for (const j of jobs) {
      const m = j.body.rollup.metrics;
      expect(Array.isArray(m)).toBe(true);
      expect(m.length).toBeGreaterThan(0);
      const recv = m.find((x) => x.source_field === 'received_at');
      expect(recv).toBeDefined();
      const types = recv.metrics.flatMap((x) => Object.keys(x));
      expect(types).toContain('value_count');
    }
  });

  it('client-hourly rolls up the single canonical mac_address dimension', () => {
    // Regression for the chained-3-mac-fields bug: rolling up client_mac +
    // wifi_client_mac + dhcp_mac as separate dimensions Cartesian-products the
    // buckets and drops events that populate only one mac field. Must be one
    // terms dimension on the canonical mac_address (parity with SQLite/WardSONDB).
    const j = jobs.find((x) => x.id === 'siem-rollup-client-hourly');
    const terms = j.body.rollup.dimensions.filter((d) => d.terms);
    expect(terms).toHaveLength(1);
    expect(terms[0].terms.source_field).toBe('mac_address');
  });

  it('5m rollup uses 5m fixed_interval; hourly rollups use 1h', () => {
    const fiveMin = jobs.find((j) => j.id === 'siem-rollup-5m');
    expect(fiveMin.body.rollup.dimensions[0].date_histogram.fixed_interval).toBe('5m');

    for (const id of ['ip-hourly', 'port-hourly', 'sig-hourly', 'client-hourly']) {
      const j = jobs.find((x) => x.id === `siem-rollup-${id}`);
      expect(j.body.rollup.dimensions[0].date_histogram.fixed_interval).toBe('1h');
    }
  });

  it('honors a custom prefix', () => {
    const custom = buildRollupJobs('prod-');
    expect(custom[0].body.rollup.source_index).toBe('prod-events');
    expect(custom[0].body.rollup.target_index).toBe('prod-rollup-5m');
    expect(custom[0].id).toBe('prod-rollup-5m');
  });
});
