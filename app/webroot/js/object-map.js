/*
 * "Show on map" for geolocation, gpx, uav and geojson objects
 * (Elements/Objects/object_map_button.ctp), drawn with Leaflet in the
 * main modal.
 *
 * Feature names and properties come from shared events, so popups are
 * built as DOM nodes: Leaflet would assign a string popup as HTML.
 */
(function () {
    'use strict';

    if (window._objectMapBound) {
        return;
    }
    window._objectMapBound = true;

    var TRACK_COLOUR = '#3388ff';
    var ROUTE_COLOUR = '#e8590c';

    function el(tag, className, text) {
        var node = document.createElement(tag);
        if (className) {
            node.className = className;
        }
        if (text !== undefined) {
            node.textContent = text;
        }
        return node;
    }

    function popup(rows) {
        var box = el('div', 'small');
        rows.forEach(function (row) {
            var line = el('div');
            if (row[0] !== null) {
                line.appendChild(el('strong', '', row[0] + ': '));
            }
            line.appendChild(document.createTextNode(row[1]));
            box.appendChild(line);
        });
        return box;
    }

    function plural(count, one, many) {
        return count + ' ' + (count === 1 ? one : many);
    }

    function drawPoint(map, spec) {
        var lat = parseFloat(spec.lat);
        var lon = parseFloat(spec.lon);
        if (isNaN(lat) || isNaN(lon)) {
            return 'No usable coordinates.';
        }
        var at = L.latLng(lat, lon);
        L.marker(at).addTo(map);
        map.setView(at, 14);
        var info = lat.toFixed(6) + ', ' + lon.toFixed(6);
        var radiusKm = parseFloat(spec.radius);
        if (!isNaN(radiusKm) && radiusKm > 0) {
            var circle = L.circle(at, {
                radius: radiusKm * 1000,
                color: TRACK_COLOUR,
                fillOpacity: 0.15,
                weight: 2
            }).addTo(map);
            map.fitBounds(circle.getBounds(), {padding: [20, 20]});
            map.addControl(radiusToggle(map, circle));
            info += ' · radius ' + radiusKm + ' km';
        }
        return info;
    }

    function radiusToggle(map, circle) {
        var Toggle = L.Control.extend({
            options: {position: 'topleft'},
            onAdd: function () {
                var bar = L.DomUtil.create('div', 'leaflet-bar leaflet-control');
                var link = L.DomUtil.create('a', '', bar);
                link.href = '#';
                link.title = 'Toggle radius';
                link.setAttribute('role', 'button');
                link.innerHTML = '<i class="far fa-circle"></i>';
                L.DomEvent.disableClickPropagation(bar);
                L.DomEvent.on(link, 'click', function (e) {
                    L.DomEvent.preventDefault(e);
                    var shown = map.hasLayer(circle);
                    shown ? map.removeLayer(circle) : map.addLayer(circle);
                    link.style.opacity = shown ? '0.5' : '1';
                });
                return bar;
            }
        });
        return new Toggle();
    }

    function gpxPoints(nodes) {
        var points = [];
        nodes.forEach(function (node) {
            var lat = parseFloat(node.getAttribute('lat'));
            var lon = parseFloat(node.getAttribute('lon'));
            if (!isNaN(lat) && !isNaN(lon)) {
                points.push(L.latLng(lat, lon));
            }
        });
        return points;
    }

    function childName(node) {
        var name = node.querySelector(':scope > name');
        return name ? name.textContent.trim() : '';
    }

    function drawGpx(map, text) {
        var gpx = new DOMParser().parseFromString(text, 'application/xml');
        if (gpx.querySelector('parsererror')) {
            return 'The attachment is not valid GPX.';
        }
        var bounds = L.latLngBounds();
        var waypoints = 0, tracks = 0, routes = 0;

        gpx.querySelectorAll('wpt').forEach(function (wpt) {
            var at = gpxPoints([wpt])[0];
            if (!at) {
                return;
            }
            var marker = L.marker(at).addTo(map);
            var name = childName(wpt);
            if (name) {
                marker.bindPopup(popup([[null, name]]));
            }
            bounds.extend(at);
            waypoints++;
        });
        gpx.querySelectorAll('trk').forEach(function (trk) {
            var drawn = false;
            trk.querySelectorAll('trkseg').forEach(function (seg) {
                var points = gpxPoints(seg.querySelectorAll('trkpt'));
                if (points.length) {
                    var line = L.polyline(points, {color: TRACK_COLOUR, weight: 3}).addTo(map);
                    line.bindPopup(popup([['Track', childName(trk) || '—']]));
                    bounds.extend(line.getBounds());
                    drawn = true;
                }
            });
            tracks += drawn ? 1 : 0;
        });
        gpx.querySelectorAll('rte').forEach(function (rte) {
            var points = gpxPoints(rte.querySelectorAll('rtept'));
            if (points.length) {
                var line = L.polyline(points, {color: ROUTE_COLOUR, weight: 3, dashArray: '6 6'}).addTo(map);
                line.bindPopup(popup([['Route', childName(rte) || '—']]));
                bounds.extend(line.getBounds());
                routes++;
            }
        });

        if (bounds.isValid()) {
            map.fitBounds(bounds, {padding: [20, 20]});
        }
        var parts = [];
        if (tracks) parts.push(plural(tracks, 'track', 'tracks') + ' (solid)');
        if (routes) parts.push(plural(routes, 'route', 'routes') + ' (dashed)');
        if (waypoints) parts.push(plural(waypoints, 'waypoint', 'waypoints'));
        return parts.length ? parts.join(' · ') : 'No geographic data found.';
    }

    function drawGeojson(map, data) {
        var types = {};
        var count = 0;
        var layer = L.geoJSON(data, {
            onEachFeature: function (feature, featureLayer) {
                count++;
                if (feature.geometry && feature.geometry.type) {
                    types[feature.geometry.type] = true;
                }
                var props = feature.properties || {};
                var rows = Object.keys(props).filter(function (key) {
                    return props[key] !== null && props[key] !== undefined;
                }).map(function (key) {
                    var value = props[key];
                    return [key, typeof value === 'object' ? JSON.stringify(value) : String(value)];
                });
                if (rows.length) {
                    featureLayer.bindPopup(popup(rows));
                }
            }
        }).addTo(map);
        var bounds = layer.getBounds();
        if (bounds.isValid()) {
            map.fitBounds(bounds, {padding: [20, 20]});
        }
        if (!count) {
            return 'No geographic data found.';
        }
        var names = Object.keys(types);
        return plural(count, 'feature', 'features') + (names.length ? ' (' + names.join(', ') + ')' : '');
    }

    function draw(map, spec, info) {
        if (spec.kind === 'point') {
            info.textContent = drawPoint(map, spec);
            return;
        }
        info.textContent = 'Loading…';
        var url = baseurl + '/attributes/download/' + encodeURIComponent(spec.attachment);
        fetch(url, {credentials: 'same-origin'})
            .then(function (response) {
                if (!response.ok) {
                    throw new Error(response.status);
                }
                return response.text();
            })
            .then(function (text) {
                info.textContent = spec.kind === 'geojson'
                    ? drawGeojson(map, JSON.parse(text))
                    : drawGpx(map, text);
            })
            .catch(function () {
                info.textContent = spec.kind === 'geojson'
                    ? 'The attachment could not be loaded as GeoJSON.'
                    : 'The attachment could not be loaded.';
            });
    }

    function open(button) {
        var modalEl = document.getElementById('mainModal');
        var body = document.getElementById('mainModalBody');
        if (!modalEl || !body || !window.L) {
            return;
        }
        var spec = JSON.parse(button.getAttribute('data-object-map'));
        var tileUrl = button.getAttribute('data-tile-url');

        var header = el('div', 'modal-header py-2');
        var title = el('h5', 'modal-title d-flex align-items-center gap-2');
        title.appendChild(el('i', 'fas fa-map-location-dot text-success'));
        title.appendChild(document.createTextNode(button.getAttribute('data-title') || ''));
        var close = el('button', 'btn-close');
        close.type = 'button';
        close.setAttribute('data-bs-dismiss', 'modal');
        close.setAttribute('aria-label', 'Close');
        header.appendChild(title);
        header.appendChild(close);
        var mapBox = el('div', 'ov-object-map');
        var info = el('div', 'ov-object-map-info px-3 py-2 text-muted');

        body.replaceChildren(header, mapBox, info);
        setModalSize('lg');

        var map = null;
        modalEl.addEventListener('shown.bs.modal', function () {
            map = L.map(mapBox);
            L.tileLayer(tileUrl + '/hot/{z}/{x}/{y}.png', {
                maxZoom: 21,
                maxNativeZoom: 20,
                attribution: '&copy; OpenStreetMap contributors'
            }).addTo(map);
            map.setView([0, 0], 2);
            draw(map, spec, info);
        }, {once: true});
        modalEl.addEventListener('hidden.bs.modal', function () {
            if (map) {
                map.remove();
            }
        }, {once: true});
        bootstrap.Modal.getOrCreateInstance(modalEl).show();
    }

    document.addEventListener('click', function (event) {
        var button = event.target.closest && event.target.closest('[data-object-map]');
        if (button) {
            event.preventDefault();
            open(button);
        }
    });
})();
