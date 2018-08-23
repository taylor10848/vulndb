function addItem(items, key, value) {
    if (value) {
        items.push({ key: key, value: value });
    }
}

polarity.export = PolarityComponent.extend({
    details: Ember.computed.alias('block.data.details'),
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

                result.products.forEach(product => {
                    product.versions = product.versions.slice(0,5);
                });

                return {
                    title: result.title,
                    items: items,
                    classifications: result.classifications,
                    authors: result.authors,
                    products: result.products.slice(0,5),
                    metrics: result.cvss_metrics,
                    vendors: result.vendors
                };
            });
        } catch (e) {
            console.error(e);
            throw e;
        }
    })
});
