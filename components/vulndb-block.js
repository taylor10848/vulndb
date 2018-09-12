polarity.export = PolarityComponent.extend({
    init() {
        this._super(...arguments);
        this.set('results', Ember.A([]));
    },
    details: Ember.computed.alias('block.data.details'),
    observer: Ember.on('init', Ember.observer('block.data.details', function () {
        let results = this.get('block.data.details');
        this.set('results', results);
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
