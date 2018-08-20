function addItem(items, key, value) {
    if (value) {
        let show = !!hideKey[key];
        items.push({ key: key, value: value, hideable: isHideableKey(key), show: show });
    }
}

function isHideableKey(key) {
    return [
        'Description',
        'Solution'
    ].includes(key);
}

let hideKey = {};

polarity.export = PolarityComponent.extend({
    details: Ember.computed.alias('block.data.details'),
    show: Ember.computed('block.data.details', function () {
        return !hideKey;
    }),
    results: Ember.computed('block.data.details', function () {
        try {
            return this.get('block.data.details').map(result => {
                let items = [];
                // addItem(items, 'Description', result.description);
                addItem(items, 'Discovery Date', result.discovery_date);
                addItem(items, 'Disclosure Date', result.disclosure_date);
                addItem(items, 'Exploit Publish Date', result.exploit_publish_date);
                addItem(items, 'Solution Date', result.solution_date);
                addItem(items, 'Keywords', result.keywords);
                // addItem(items, 'Solution', result.solution);

                // TODO fifugre out what value should be returned
                //let references = result.ext_references.map(reference => reference.type);
                // TODO figure out what should be displayed
                //let texts = result.ext_text.map(text => text.type);
                // TODO metrics
                // let metrics = result.cvss_metrics.map(metric => metric);

                return {
                    title: result.title,
                    items: items,
                    classifications: result.classifications,
                    authors: result.authors
                };
            });
        } catch (e) {
            console.error(e);
            throw e;
        }
    }),
    actions: {
        toggle: function (key) {
            hideKey[key] = !hideKey[key]
        }
    }
});
