const { flatStringParams } = require('../../src/utils/query');

describe('flatStringParams', () => {
  it('keeps string-valued entries unchanged', () => {
    expect(flatStringParams({ period: '24h', src_ip: '1.2.3.4', limit: '50' }))
      .toEqual({ period: '24h', src_ip: '1.2.3.4', limit: '50' });
  });

  it('drops nested objects (qs bracket syntax → operator injection)', () => {
    expect(flatStringParams({ src_ip: { $ne: 'x' }, action: 'block' }))
      .toEqual({ action: 'block' });
  });

  it('drops arrays from repeated keys', () => {
    expect(flatStringParams({ src_ip: ['1.1.1.1', '2.2.2.2'], dst_ip: '3.3.3.3' }))
      .toEqual({ dst_ip: '3.3.3.3' });
  });

  it('drops numbers, booleans, null and undefined', () => {
    expect(flatStringParams({ a: 1, b: true, c: null, d: undefined, e: '' }))
      .toEqual({ e: '' });
  });

  it('ignores inherited keys and refuses prototype-polluting keys', () => {
    const proto = { inherited: 'nope' };
    const query = Object.create(proto);
    query.own = 'yes';
    expect(flatStringParams(query)).toEqual({ own: 'yes' });

    const nullProto = Object.create(null);
    nullProto.__proto__ = 'x';
    nullProto.constructor = 'y';
    nullProto.ok = 'z';
    const out = flatStringParams(nullProto);
    expect(out).toEqual({ ok: 'z' });
    expect(Object.getPrototypeOf(out)).toBe(Object.prototype);
  });

  it('returns an empty object for non-object input', () => {
    expect(flatStringParams(undefined)).toEqual({});
    expect(flatStringParams(null)).toEqual({});
    expect(flatStringParams('a=b')).toEqual({});
  });
});
