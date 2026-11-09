/* Exercise the actual collection-selection handlers with a large selection. */
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const source = fs.readFileSync(__dirname + '/../webroot/js/misp.js', 'utf8');
function handler(name) {
    const start = source.indexOf('function ' + name + '(');
    const end = source.indexOf('\nfunction ', start + 1);
    assert(start !== -1 && end !== -1);
    return source.slice(start, end);
}
const selected = Array.from({length: 5000}, (_, index) => ({id: index + 1}));
let request;
function jquery(value) {
    if (value === '.select:checked') {
        return {each: fn => selected.forEach(item => fn.call(item))};
    }
    return {data: () => value.id};
}
jquery.ajax = value => { request = value; };
const context = {baseurl: '/misp', window: {csrfToken: 'fresh-page-csrf-token'}, $: jquery,
    sanitizeUrlForTraversal: value => value};
vm.runInNewContext(handler('openGenericModalPost') + '\n' + handler('multiSelectExportEvents'), context);
context.multiSelectExportEvents();
assert.equal(request.type, 'post');
assert.equal(request.url, '/misp/events/restSearchExport');
assert.equal(request.headers['X-CSRF-Token'], 'fresh-page-csrf-token');
assert.deepEqual(JSON.parse(request.data.eventid), selected.map(item => item.id));
console.log('PASS: 5000 selected IDs travel in POST data with the CSRF token, not in the URL.');
