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

polarity.export = PolarityComponent.extend({
    init() {
        this._super(...arguments);
        this.set('results', Ember.A([]));
    },
    details: Ember.computed.alias('block.data.details'),
    observer: Ember.on('init', Ember.observer('block.data.details', function () {
        try {
            let results = this.get('block.data.details').map(result => {
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
                    title: result.title,
                    items: items,
                    classifications: result.classifications,
                    authors: authors,
                    products: result.products.slice(0, 5),
                    metrics: result.cvss_metrics,
                    references: result.ext_references,
                    vtems: result.vtems,
                    vendors: result.vendors
                };
            });
            this.set('results', results);
        } catch (e) {
            console.error(e);
        }
    })),
    actions: {
        toggle: function (key) {
            let results = this.get('results');
            results = JSON.parse(JSON.stringify(results));

            results.forEach(result => {
                result.items.forEach(item => {
                    if (item.key === key) {
                        console.error('found item to toggle, now ' + !item.show);
                        item.show = !item.show;
                    }
                });
            });

            this.set('results', results);
            this.notifyPropertyChange('results');
        }
    }
});
