const { validateSettingValue } = require('../../src/api/routes/settings');

describe('validateSettingValue', () => {
  const str = { key: 'x.s', type: 'string' };
  const num = { key: 'x.n', type: 'number' };
  const opt = { key: 'x.o', type: 'string', options: ['a', 'b'] };
  const secret = { key: 'x.k', type: 'string', sensitivity: 'private' };

  it('accepts strings and numbers (including the empty-string reset form)', () => {
    expect(validateSettingValue(str, 'anything')).toBeNull();
    expect(validateSettingValue(num, '42')).toBeNull();
    expect(validateSettingValue(num, 42)).toBeNull();
    expect(validateSettingValue(num, '')).toBeNull();
  });

  it('rejects non-numeric values for number entries', () => {
    expect(validateSettingValue(num, 'abc')).toMatch(/number/);
  });

  it('enforces the options list', () => {
    expect(validateSettingValue(opt, 'a')).toBeNull();
    expect(validateSettingValue(opt, 'c')).toMatch(/one of: a, b/);
    expect(validateSettingValue(opt, '')).toMatch(/one of/);
  });

  it('rejects the masked echo for private entries', () => {
    expect(validateSettingValue(secret, '••••••••abcd')).toMatch(/masked/);
    expect(validateSettingValue(secret, 'real-key')).toBeNull();
  });
});
