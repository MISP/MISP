// The GPX and GeoJSON map popups in misp.js show text out of an attachment
// that any event author can upload, and Leaflet renders popup content as
// HTML: the text has to be escaped first.
//
// Run with:
//   node --test app/Test/js/GeoMapPopups.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { lines, run } from './browserScript.mjs';

const UPLOADED = `x'"<i>y`;
const ESCAPED = 'x&#039;&quot;&lt;i&gt;y';

const escapeHtml = lines('misp.js', 'function escapeHtml(', '}');
const map = { setView() {}, fitBounds() {}, invalidateSize() {} };

function leaflet(popups) {
    const layer = {
        addTo() { return this; },
        bindPopup(html) { popups.push(html); return this; },
    };
    return {
        latLng: () => ({}),
        latLngBounds: () => ({ extend() {}, isValid: () => false }),
        marker: () => Object.create(layer),
        polyline: () => Object.create(layer),
        geoJSON(data, options) {
            data.features.forEach(feature => options.onEachFeature(feature, Object.create(layer)));
            return { addTo() { return this; }, getBounds: () => ({ isValid: () => false }) };
        },
    };
}

test('a GPX waypoint name is shown as text', () => {
    const popups = [];
    const waypoint = {
        getAttribute: () => '1',
        querySelector: () => ({ textContent: UPLOADED }),
    };
    const gpx = { querySelectorAll: selector => (selector === 'wpt' ? [waypoint] : []) };
    const page = run(escapeHtml + '\n' + lines('misp.js', 'function parseGpxToLayers(', '}'), {
        L: leaflet(popups),
        DOMParser: class { parseFromString() { return gpx; } },
    });

    page.parseGpxToLayers('<gpx/>', map);
    assert.deepEqual(popups, [ESCAPED]);
});

test('GeoJSON property names and values are shown as text', () => {
    const popups = [];
    const handlers = {};
    const $ = () => ({
        data: key => ({ 'attachment-id': 1, 'tile-url': '' })[key],
        text() {},
        on(event, selector, handler) { handlers[selector] = handler; },
    });
    $.ajax = options => options.success({
        type: 'FeatureCollection',
        features: [{ type: 'Feature', geometry: null, properties: { [UPLOADED]: UPLOADED } }],
    });
    run(escapeHtml + '\n' + lines('misp.js', '$(document).on("click", ".geojson-map-icon"', '});'), {
        $,
        document: {},
        baseurl: '',
        L: leaflet(popups),
        openMapPopover: (title, tileUrl, callback) => callback(map),
        setTimeout: () => {},
    });

    handlers['.geojson-map-icon'].call({});
    assert.deepEqual(popups, [`<strong>${ESCAPED}</strong>: ${ESCAPED}`]);
});
