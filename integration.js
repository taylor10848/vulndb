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
            },
            qs: {
                vtem: true,
                show_cpe: true,
                full_reference_url: true
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
                        tags['CVSS Score: ' + metric.score] = true;
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
        results.forEach(result => {
            if (result.data) {
                result.data.details = result.data.details.map(formatForView);
            }
        });
        callback(err, results)
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

function addItem(items, key, value) {
    if (value) {
        items.push({ key: key, value: value, hideable: isHideableKey(key), show: !isHideableKey(key) });
    }
}

function isHideableKey(key) {
    return [
        'Description',
        'Solution'
    ].includes(key);
}

// Format the response for the view
function formatForView(result) {
    let items = [];
    addItem(items, 'Description', result.description);
    addItem(items, 'Discovery Date', result.discovery_date);
    addItem(items, 'Disclosure Date', result.disclosure_date);
    addItem(items, 'Exploit Publish Date', result.exploit_publish_date);
    addItem(items, 'Solution Date', result.solution_date);
    addItem(items, 'Keywords', result.keywords);
    addItem(items, 'Solution', result.solution);

    result.products.forEach(product => {
        product.versions = product.versions.slice(0, 5);
        product.versions.reverse();
    });

    let authors = result.authors.map(author => {
        let items = [];
        addItem(items, 'Name', author.name);
        addItem(items, 'Company', author.company);
        addItem(items, 'Country', author.country);
        addItem(items, 'Email', author.email);
        return { fields: items };
    });

    return {
        vulndb_id: result.vulndb_id,
        title: result.title,
        items: items,
        classifications: categorizeClassifications(result.classifications),
        authors: authors,
        products: result.products.slice(0, 5),
        metrics: result.cvss_metrics,
        references: result.ext_references,
        vtems: result.vtems,
        vendors: result.vendors
    };
}

let classificationIdToCategory = {};

function addClassificationIdToCategory(category, ids) {
    ids.forEach(id => {
        classificationIdToCategory[id] = category;
    });
}

addClassificationIdToCategory('Location', [1, 4, 2, 42, 46, 3, 31, 32, 5]);
addClassificationIdToCategory('Attack Type', [6, 7, 11, 68, 12, 13, 14, 15, 16]);
addClassificationIdToCategory('Impact', [17, 18, 19, 20]);
addClassificationIdToCategory('Solution', [35, 34, 38, 36, 50, 37, 45, 60]);
addClassificationIdToCategory('Exploit', [63, 21, 55, 54, 24, 61, 39]);
addClassificationIdToCategory('Disclosure', [64, 41, 40, 49, 52, 43, 44, 53, 57, 65, 66, 67]);
addClassificationIdToCategory('VulnDB', [47, 48, 29, 28, 26, 62, 51, 56, 58, 59]);

function categorizeClassifications(classifications) {
    let classificationsByCategoriesMap = {};

    classifications.forEach(classification => {
        let classificationCategory = classificationsByCategoriesMap[classificationIdToCategory[classification.id]];

        if (!classificationCategory) {
            classificationCategory = classificationsByCategoriesMap[classificationIdToCategory[classification.id]] = [];
        }

        classificationCategory.push(classification.longname);
    });

    let classificationsByCategories = [];

    Object.keys(classificationsByCategoriesMap).forEach(category => {
        classificationsByCategories.push({
            category: category,
            classifications: classificationsByCategoriesMap[category]
        });
    });

    return classificationsByCategories;
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
