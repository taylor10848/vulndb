let async = require('async');
let config = require('./config/config');
let request = require('request');

let Logger;

let requestWithDefaults;
let requestOptions = {};

const host = 'vulndb.cyberriskanalytics.com';

function handleRequestError(request) {
    return (options, expectedStatusCode, callback) => {
        return request(options, (err, resp, body) => {
            if (err || resp.statusCode !== expectedStatusCode) {
                Logger.error(`error during http request to ${options.url}`, { error: err, status: resp ? resp.statusCode : 'unknown' });
                callback({ error: err, statusCode: resp ? resp.statusCode : 'unknown' });
            } else {
                callback(null, body);
            }
        });
    };
}

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

        requestWithDefaults({
            url: `https://${targetHost}/api/v1/vulnerabilities/${entity.value}/find_by_cve_id`,
            oauth: {
                consumer_key: options.key,
                consumer_secret: options.secret
            }
        }, 200, function (err, body) {
            Logger.trace('results from vulndb', { results: body });
            if (err) {
                if (err.statusCode === 404) {
                    Logger.warn(`No CVE entity found for key ${entity.value}`);
                    results.push({
                        entity: entity,
                        data: null
                    });
                    done();
                } else {
                    done(err);
                }
            } else {
                Logger.trace('result sent to client', { results: body.results });
                let tags = {};

                body.results.forEach(result => {
                    result.classifications.forEach(classification => {
                        tags[classification.longname] = true;
                    });
                    result.cvss_metrics.forEach(metric => {
                        tags[metric.access_vector] = true;
                    });
                });

                results.push({
                    entity: entity,
                    data: {
                        summary: Object.keys(tags),
                        details: body.results
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

    requestOptions.json = true;

    requestWithDefaults = handleRequestError(request.defaults(requestOptions));
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

    validateStringOption(errors, options, 'key', 'You must supply a client key.');
    validateStringOption(errors, options, 'secret', 'You must supply a client secret.');

    callback(null, errors);
}

module.exports = {
    doLookup: doLookup,
    startup: startup,
    validateOptions: validateOptions
};
