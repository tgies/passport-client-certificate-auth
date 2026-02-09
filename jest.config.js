/** @type {import('jest').Config} */
export default {
    roots: [
        '<rootDir>/test',
        '<rootDir>/lib',
    ],
    testMatch: [
        '**/test/test-strategy.js',
        '**/test/test-integration-*.js',
        '**/test/test-e2e-*.js',
    ],
    collectCoverageFrom: [
        'lib/**/*.js',
    ],
    coverageThreshold: {
        global: {
            branches: 100,
            functions: 100,
            lines: 100,
            statements: 100,
        },
    },
    testTimeout: 10000,
    verbose: true,
};
