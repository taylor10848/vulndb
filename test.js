let integration = require('./integration');

describe('vulndb', () => {
    it('should get the token', (done) => {
        integration.doLookup([], {
            testHost: 'vulndb.cyberriskanalytics.com',
            key: '',
            secret: ''
        }, (err, token) => {
            console.error(err);
            console.log(token);
            done(err);
        });
    });
});
