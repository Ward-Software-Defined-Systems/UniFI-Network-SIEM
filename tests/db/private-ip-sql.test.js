const Database = require('better-sqlite3');
const { buildPrivateIpFilter } = require('../../src/db/utils/private-ip-sql');
const { isPrivateIp } = require('../../src/utils/ip-utils');

describe('buildPrivateIpFilter', () => {
  // Spin up an in-memory SQLite DB so we can verify the generated SQL
  // actually filters the same way isPrivateIp does. This keeps the JS
  // and SQL implementations in lockstep.
  let db;
  beforeAll(() => {
    db = new Database(':memory:');
    db.exec('CREATE TABLE ips (ip TEXT)');
    const insert = db.prepare('INSERT INTO ips (ip) VALUES (?)');
    const samples = [
      // private IPv4
      '10.0.0.1', '10.255.255.254',
      '172.16.0.1', '172.31.255.254',
      '192.168.0.1', '192.168.255.254',
      '100.64.0.1', '100.127.255.255',  // CGNAT inside /10
      '127.0.0.1',
      '169.254.1.1',
      '224.0.0.1', '239.255.255.255',  // multicast
      '0.0.0.0', '255.255.255.255',
      // public IPv4
      '8.8.8.8', '1.1.1.1',
      '100.128.0.1', '100.150.0.1', '100.199.0.1',  // OUTSIDE CGNAT — H4 fix
      '11.0.0.1',
      '172.15.255.254', '172.32.0.1',
      // IPv6 (coarse exclusion)
      '::1', 'fe80::1', '2001:db8::1', '::ffff:8.8.8.8',
    ];
    for (const ip of samples) insert.run(ip);
  });
  afterAll(() => db?.close());

  it('excluded set matches isPrivateIp on the same inputs (incl. H4 boundary)', () => {
    const sql = buildPrivateIpFilter('ip');
    const filtered = db.prepare(`SELECT ip FROM ips WHERE ${sql}`).all().map((r) => r.ip);

    const allRows = db.prepare('SELECT ip FROM ips').all().map((r) => r.ip);
    for (const ip of allRows) {
      const sqlSaysPublic = filtered.includes(ip);
      const jsSaysPublic = !isPrivateIp(ip);
      // SQL filter only handles IPv4 explicitly; IPv6 strings get coarse-
      // excluded by the `'%:%'` clause regardless of public/private.
      // For IPv4 inputs the two predicates must agree exactly.
      if (!ip.includes(':')) {
        expect({ ip, sqlSaysPublic, jsSaysPublic }).toEqual({ ip, sqlSaysPublic: jsSaysPublic, jsSaysPublic });
      } else {
        // IPv6 always excluded by the SQL filter
        expect({ ip, sqlSaysPublic }).toEqual({ ip, sqlSaysPublic: false });
      }
    }
  });

  it('100.128 and beyond are NOT excluded (H4 fix)', () => {
    const sql = buildPrivateIpFilter('ip');
    const stmt = db.prepare(`SELECT ip FROM ips WHERE ip = ? AND (${sql})`);
    expect(stmt.get('100.128.0.1')?.ip).toBe('100.128.0.1');
    expect(stmt.get('100.150.0.1')?.ip).toBe('100.150.0.1');
    expect(stmt.get('100.199.0.1')?.ip).toBe('100.199.0.1');
  });

  it('CGNAT 100.64-100.127 IS excluded', () => {
    const sql = buildPrivateIpFilter('ip');
    const stmt = db.prepare(`SELECT ip FROM ips WHERE ip = ? AND (${sql})`);
    expect(stmt.get('100.64.0.1')).toBeUndefined();
    expect(stmt.get('100.127.255.255')).toBeUndefined();
  });

  it('multicast and broadcast are excluded', () => {
    const sql = buildPrivateIpFilter('ip');
    const stmt = db.prepare(`SELECT ip FROM ips WHERE ip = ? AND (${sql})`);
    expect(stmt.get('224.0.0.1')).toBeUndefined();
    expect(stmt.get('239.255.255.255')).toBeUndefined();
    expect(stmt.get('255.255.255.255')).toBeUndefined();
    expect(stmt.get('0.0.0.0')).toBeUndefined();
  });
});
