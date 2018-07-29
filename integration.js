let async = require('async');
let config = require('./config/config');
let request = require('request');

let Logger;

let requestWithDefaults;
let requestOptions = {};

const host = 'vulndb.cyberriskanalytics.com';

let responseJson = `
{
    "results": [
        {
            "vulndb_id": "1",
            "title": "2",
            "disclosure_date": "3",
            "discovery_date": "4",
            "exploit_publish_date": "5",
            "keywords": "6",
            "description": "7",
            "solution": "8",
            "manual_notes": "9",
            "t_description": "10",
            "solution_date": "11",
            "vendor_informed_date": "12",
            "vendor_ack_date": "13",
            "third_party_solution_date": "14",
            "classifications": [{
                    "id": "15",
                    "name": "16",
                    "longname": "17",
                    "description": "18",
                    "mediumtext": "19"
            }],
            "authors": [{
                    "id": "20",
                    "name": "21",
                    "company": "22",
                    "email": "23",
                    "company_url": "24",
                    "country": "25"
            }],
            "ext_references": [{
                    "value": "26",
                    "type": "27"
            }],
            "ext_texts": [{
                    "value": "28",
                    "type": "29"
            }],
            "cvss_metrics": [{
                "id": "30",
                "access_vector": "31",
                "access_complexity": "32",
                "authentication": "33",
                "confidentiality_impact": "34",
                "integrity_impact": "35",
                "availability_impact": "36",
                "source": "37",
                "cve_id": "38",
                "score": "39",
                "calculated_cvss_base_score": "40"
            }]
        }
    ]
}
`;

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
            if (err) {
                done(err);
            } else {
                results.push({
                    entity: entity,
                    data: {
                        summary: ['test'],
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

    // requestWithDefaults = handleRequestError(request.defaults(requestOptions));
    requestWithDefaults = (_0, _1, cb) => {
        cb(null, JSON.parse(responseJson));
    };
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

    validateStringOption(errors, options, 'key', 'You must client key.');
    validateStringOption(errors, options, 'secret', 'You must client secret.');

    callback(null, errors);
}

module.exports = {
    doLookup: doLookup,
    startup: startup,
    validateOptions: validateOptions
};
