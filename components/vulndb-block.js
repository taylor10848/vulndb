polarity.export = PolarityComponent.extend({
    details: Ember.computed.alias('block.data.details'),
    results: Ember.computed('block.data.details', function () {
        try {
            return this.get('block.data.details').map(result => {
                let items = [];
                items.push({ key: 'Description', value: result.description });
                items.push({ key: 'Discovery Date', value: result.discovery_date });
                items.push({ key: 'Disclosure Date', value: result.disclosure_date });
                items.push({ key: 'Exploit Publish Date', value: result.exploit_publish_date });
                items.push({ key: 'Solution Date', value: result.solution_date });
                items.push({ key: 'Keywords', value: result.keywords });
                items.push({ key: 'Solution', value: result.solution });

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
    })
});
