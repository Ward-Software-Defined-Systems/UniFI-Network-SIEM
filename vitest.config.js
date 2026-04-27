module.exports = {
  test: {
    include: ['tests/**/*.test.js'],
    environment: 'node',
    globals: true,
    testTimeout: 5000,
    reporters: 'default',
  },
};
