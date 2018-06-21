polarity.export = PolarityComponent.extend({
    details: Ember.computed.alias('block.data.details'),
    tags: Ember.computed('block.data.details', function () {
        // collect the values to display in the summary and return as a list 
        // of string

        return ['example', 'tags', 'to', 'display'];
    })
});
