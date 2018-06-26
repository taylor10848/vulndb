let async = require('async');
let config = require('./config/config');
let request = require('request');

let Logger;

let requestWithDefaults;
let requestOptions = {};

const host = 'vulndb2.cyberriskanalytics.com';

function doLookup(entities, options, callback) {
    let targetHost = options.testHost || host;
    let results = [];

    async.each(entities, (entity, done) => {
        if (entity.types.indexOf('custom.cve') === -1) {
            Logger.warn(`received an entity ${entity.type} ${entity.types} type not CVE, ignoring entity`);
            results.push({
                entity: entity,
                data: null
            });
            done();
            return;
        }

        request({
            url: `https://${targetHost}/api/v1/vulnerabilities/${entity.value}/find_by_cve_id`,
            oauth: {
                consumer_key: options.key,
                consumer_secret: options.secret
            }
        }, function (err, res, body) {
            if (err || res.statusCode != 200) {
                Logger.error('Entity lookup failed for ' + entity.value, { error: err, statusCode: res.statusCode });
                done({ error: err, statusCode: res.statusCode });
            } else {
                results.push({
                    entity: entity,
                    data: {
                        summary: ['test'],
                        details: body
                    }
                });
                done();
            }
        });
    }, err => {
        callback(err, results);
    });
}

function startup(logger) {
    Logger = logger;

    if (typeof config.request.cert === 'string' && config.request.cert.length > 0) {
        requestOptions.cert = fs.readFileSync(config.request.cert);
    }

    if (typeof config.request.key === 'string' && config.request.key.length > 0) {
        requestOptions.key = fs.readFileSync(config.request.key);
    }

    if (typeof config.request.passphrase === 'string' && config.request.passphrase.length > 0) {
        requestOptions.passphrase = config.request.passphrase;
    }

    if (typeof config.request.ca === 'string' && config.request.ca.length > 0) {
        requestOptions.ca = fs.readFileSync(config.request.ca);
    }

    if (typeof config.request.proxy === 'string' && config.request.proxy.length > 0) {
        requestOptions.proxy = config.request.proxy;
    }

    if (typeof config.request.rejectUnauthorized === 'boolean') {
        requestOptions.rejectUnauthorized = config.request.rejectUnauthorized;
    }

    requestWithDefaults = request.defaults(requestOptions);
}

function validateStringOption(errors, options, optionName, errMessage) {
    if (typeof options[optionName].value !== 'string' ||
        (typeof options[optionName].value === 'string' && options[optionName].value.length === 0)) {
        errors.push({
            key: optionName,
            message: errMessage
        });
    }
}

function validateOptions(options, callback) {
    let errors = [];

    // Example of how to validate a string option
    validateOption(errors, options, 'exampleKey', 'You must provide an example option.');

    callback(null, errors);
}

module.exports = {
    doLookup: doLookup,
    startup: startup,
    validateOptions: validateOptions
};
