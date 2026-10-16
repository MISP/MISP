// Value Neighbourhood — a value's occurrences drawn as the Pivot Explorer
// draws an event: the objects and attributes holding it, their events, what
// references and analyst relationships reach from them, the feeds and servers
// that know it and the values close to it.
//
// Built on window.MispPivotExplorer (pivot-explorer.js): this file is the
// value's host — its seed, its pivots and its options — and the explorer's
// builders do the drawing.
//
//   MispValueNeighbourhood.explorer(config)  the full graph, into config.containerEl
//   MispValueNeighbourhood.host(config)      the host it is built from
//   MispValueNeighbourhood.graphData(seed, kit)
//   MispValueNeighbourhood.leads / stories   what the peek and the graph read
//
// The graph opens as rows, one per event, read left to right: the value, what
// holds it there (folded into one group when an event holds it often), the
// event. An occurrence with something to follow — a reference or an analyst
// relationship reaching out of it — is a lead, and never folds.
//
// config: { value, b64, baseurl, containerEl, loaderEl, labelPlan, permitted,
//           orgUuid, siteAdmin, valueCard, text, seed? }

(function () {
    'use strict';

    var MORE_PIVOT  = 'more-occurrences';
    var WHERE_PIVOT = 'where-else';
    // What one More occurrences run lands (ValueGraph::PIVOT_BUDGET).
    var PIVOT_BUDGET = 200;

    function valueNodeId(b64) {
        return 'value:' + b64;
    }

    function valueNodeData(v, centre) {
        return {
            type:        'value',
            label:       v.value,
            value:       v.value,
            b64:         v.b64,
            'attr-type': (v.types || [])[0],
            types:       v.types,
            centre:      centre || undefined,
            description: centre ? 'This value' : (v.description || 'Value')
        };
    }

    function nearLabel(n) {
        if (n.engine === 'cidr') return 'in /' + n.closeness;
        if (n.engine === 'ssdeep') return 'ssdeep ' + n.closeness;
        if (n.engine === 'typosquat') return n.closeness ? 'look-alike · ' + n.closeness : 'look-alike';
        return n.engine;
    }

    // The relations an object files the value under, from its held attributes.
    function heldRelations(obj) {
        var held = {};
        (obj.holds || []).forEach(function (uuid) { held[uuid] = true; });
        var names = {};
        (obj.Attribute || []).forEach(function (a) {
            if (held[a.uuid] && a.object_relation) names[a.object_relation] = true;
        });
        return Object.keys(names).sort().join(', ');
    }

    // Occurrences as the explorer lands elements: each object closed with its
    // attributes, each event-level attribute free, each beside its event card,
    // and every one joined to the value node that holds it.
    function landOccurrences(kit, land, slice, valueIdOf, kind) {
        kind = kind || 'occurrence';
        var cards = slice.events || {};
        kit.mergePriorities(slice.ui_priorities);
        function card(eventId) {
            var c = cards[eventId];
            return c ? land.node(kit.eventCardNode(c)) : null;
        }
        (slice.Object || []).forEach(function (obj) {
            var c = cards[obj.event_id] || {};
            var owner = kit.provenance(obj.event_id, c.uuid);
            var node = kit.foreignObjectNode(obj, owner);
            var held = {};
            (obj.holds || []).forEach(function (uuid) { held[uuid] = true; });
            node.children.forEach(function (child) {
                if (held[child.data.uuid]) child.data.holds_value = true;
            });
            var id = land.node(node);
            var cid = card(obj.event_id);
            if (cid) land.edge(kit.inEventEdge(id, cid));
            var vid = valueIdOf(obj);
            if (vid) {
                if (kind === 'occurrence') node.data.occurrence_of = vid;
                land.edge({ id: kind + ':' + vid + ':' + id, from: vid, to: id,
                            data: { kind: kind, label: heldRelations(obj) } });
            }
        });
        (slice.Attribute || []).forEach(function (a) {
            var c = cards[a.event_id] || {};
            var data = kit.attributeNodeData(a, kit.provenance(a.event_id, c.uuid));
            var id = land.node({ id: 'attr:' + a.uuid, data: data });
            var cid = card(a.event_id);
            if (cid) land.edge(kit.inEventEdge(id, cid));
            var vid = valueIdOf(a);
            if (vid) {
                if (kind === 'occurrence') data.occurrence_of = vid;
                land.edge({ id: kind + ':' + vid + ':' + id, from: vid, to: id,
                            data: { kind: kind, label: a.type || '' } });
            }
        });
    }

    // The seed as pivotick data.
    function graphData(seed, kit) {
        var land = kit.landing();
        var centre = valueNodeId(seed.value.b64);
        land.node({ id: centre, data: valueNodeData(seed.value, true) });

        landOccurrences(kit, land, seed, function () { return centre; });

        // Reference far ends, each beside its event card.
        var cards = seed.events || {};
        var far = seed.far || {};
        (far.objects || []).forEach(function (obj) {
            var c = cards[obj.event_id] || {};
            var id = land.node(kit.foreignObjectNode(obj, kit.provenance(obj.event_id, c.uuid)));
            if (cards[obj.event_id]) land.edge(kit.inEventEdge(id, land.node(kit.eventCardNode(cards[obj.event_id]))));
        });
        (far.attributes || []).forEach(function (a) {
            var c = cards[a.event_id] || {};
            var id = land.node({ id: 'attr:' + a.uuid, data: kit.attributeNodeData(a, kit.provenance(a.event_id, c.uuid)) });
            if (cards[a.event_id]) land.edge(kit.inEventEdge(id, land.node(kit.eventCardNode(cards[a.event_id]))));
        });

        // Every id an edge may end on: nodes, and the attributes inside objects.
        var ends = {};
        land.result().nodes.forEach(function (n) {
            ends[n.id] = true;
            (n.children || []).forEach(function (c) { ends[c.id] = true; });
        });

        (seed.references || []).forEach(function (r) {
            var from = 'obj:' + r.object_uuid;
            var to = (r.referenced_type === 'object' ? 'obj:' : 'attr:') + r.referenced_uuid;
            if (!ends[from] || !ends[to]) return;
            var rel = r.relationship_type || 'related-to';
            land.edge({ id: 'ref:' + r.uuid, from: from, to: to,
                        data: { kind: 'object-reference', label: rel, uuid: r.uuid, relationship_type: rel } });
        });

        // Analyst relationships, their far ends drawn as the explorer's seed
        // draws another event's element.
        var ev = { Attribute: seed.Attribute || [], Object: seed.Object || [] };
        kit.eachAnalystRelationship(ev, function (rel, fromId, toId, farId) {
            if (!fromId || !toId || fromId === toId) return;
            if (!ends[farId]) {
                var f = kit.relationshipFarEnd(rel, farId);
                if (!f) return;
                if (f.type === 'event') {
                    land.node({ id: farId, data: kit.eventNodeData(f.record) });
                } else if (f.type === 'cluster') {
                    land.node(kit.clusterNode(farId, f.record));
                } else {
                    var owner = kit.provenance(f.event.id, f.event.uuid);
                    land.node({ id: farId, data: f.type === 'attribute'
                        ? kit.attributeNodeData(f.record, owner) : kit.objectNodeData(f.record, owner) });
                    var cid = land.node({ id: 'event:' + f.event.uuid, data: kit.eventNodeData(f.event) });
                    land.edge(kit.inEventEdge(farId, cid));
                }
                ends[farId] = true;
            }
            var type = rel.relationship_type || 'related-to';
            land.edge({ id: 'analyst:' + rel.uuid, from: fromId, to: toId,
                        data: { kind: 'analyst-relationship', label: type, authors: rel.authors,
                                orgc: rel.orgc_uuid, uuid: rel.uuid, relationship_type: type } });
        });

        // The value's feeds and servers.
        kit.sources.forEach(function (s) {
            var known = kit.sourceMap(seed, s.scope);
            Object.keys(known).forEach(function (id) {
                var srcId = land.node({ id: s.type + ':' + id, data: kit.sourceNodeData(s.type, known[id]) });
                land.edge({ id: s.kind + ':' + id, from: srcId, to: centre, data: { kind: s.kind, label: '' } });
            });
        });

        (seed.near || []).forEach(function (n) {
            var near = valueNodeData({ value: n.value, b64: n.b64, types: [], description: 'Close to this value' });
            near.near_label = nearLabel(n);
            var id = land.node({ id: valueNodeId(n.b64), data: near });
            land.edge({ id: 'near:' + n.b64, from: centre, to: id,
                        data: { kind: 'near', label: nearLabel(n), engine: n.engine } });
        });

        var out = land.result();
        markLeads(out, leads(seed, kit));
        return out;
    }

    /* ── leads: the occurrences with something to follow ───── */
    // A unit is what an occurrence lands as: the object holding the value, or
    // the event-level attribute. It is a lead when a reference or an analyst
    // relationship reaches from it (the object, or any of its attributes) to
    // something outside the unit. Far ends are gathered by node id, so eight
    // objects pointed at by one file read as one lead.
    function indexSeed(seed) {
        var units = [], unitOf = {}, record = {};
        (seed.Object || []).forEach(function (o) {
            var u = { id: 'obj:' + o.uuid, kind: 'object', rec: o, name: o.name, event_id: o.event_id, reasons: [] };
            units.push(u);
            unitOf[u.id] = u;
            record[u.id] = { type: 'object', rec: o };
            (o.Attribute || []).forEach(function (a) {
                unitOf['attr:' + a.uuid] = u;
                record['attr:' + a.uuid] = { type: 'attribute', rec: a, parent: o };
            });
        });
        (seed.Attribute || []).forEach(function (a) {
            var u = { id: 'attr:' + a.uuid, kind: 'attribute', rec: a, name: a.type, event_id: a.event_id, reasons: [] };
            units.push(u);
            unitOf[u.id] = u;
            record[u.id] = { type: 'attribute', rec: a };
        });
        var far = seed.far || {};
        (far.objects || []).forEach(function (o) {
            record['obj:' + o.uuid] = { type: 'object', rec: o };
            (o.Attribute || []).forEach(function (a) {
                record['attr:' + a.uuid] = { type: 'attribute', rec: a, parent: o };
            });
        });
        (far.attributes || []).forEach(function (a) { record['attr:' + a.uuid] = { type: 'attribute', rec: a }; });
        return { units: units, unitOf: unitOf, record: record };
    }

    // What names an object in a line of text: its highest-ranked attribute.
    function leadValue(obj, ranks) {
        var r = (ranks || {})[obj.template_uuid + '.' + obj.template_version] || {};
        var best = null, bestKey = null;
        (obj.Attribute || []).forEach(function (a, i) {
            var key = [r[a.object_relation] || 0, a.to_ids ? 1 : 0, -i];
            if (!best || key[0] > bestKey[0] || (key[0] === bestKey[0] &&
                (key[1] > bestKey[1] || (key[1] === bestKey[1] && key[2] > bestKey[2])))) {
                best = a; bestKey = key;
            }
        });
        return best ? String(best.value) : '';
    }

    function leads(seed, kit) {
        var ix = indexSeed(seed);
        var ends = {}, seen = {};

        function farEnd(id, fallback) {
            if (ends[id]) return ends[id];
            var r = ix.record[id];
            var end = { id: id, via: [], units: {}, occurrence: !!ix.unitOf[id] };
            if (r && r.type === 'object') {
                end.type = 'object';
                end.name = r.rec.name;
                end.label = leadValue(r.rec, seed.ui_priorities);
                end.event_id = r.rec.event_id;
            } else if (r) {
                end.type = 'attribute';
                end.name = r.rec.type;
                end.label = String(r.rec.value);
                end.to_ids = !!r.rec.to_ids;
                end.event_id = r.rec.event_id;
            } else if (fallback) {
                Object.assign(end, fallback);
            } else {
                return null;
            }
            ends[id] = end;
            return end;
        }

        function note(unit, endId, kind, rel, dir, fallback) {
            var key = kind + '|' + unit.id + '|' + endId + '|' + rel + '|' + dir;
            if (seen[key]) return;
            seen[key] = true;
            var end = farEnd(endId, fallback);
            if (!end) return;
            end.via.push({ kind: kind, rel: rel, dir: dir });
            end.units[unit.id] = true;
            unit.reasons.push(kind);
        }

        (seed.references || []).forEach(function (r) {
            var from = 'obj:' + r.object_uuid;
            var to = (r.referenced_type === 'object' ? 'obj:' : 'attr:') + r.referenced_uuid;
            if (!ix.record[from] || !ix.record[to]) return;
            var uf = ix.unitOf[from], ut = ix.unitOf[to];
            if (uf && uf === ut) return;
            var rel = r.relationship_type || 'related-to';
            if (uf) note(uf, ut ? ut.id : to, 'reference', rel, 'out');
            if (ut) note(ut, uf ? uf.id : from, 'reference', rel, 'in');
        });

        kit.eachAnalystRelationship({ Attribute: seed.Attribute || [], Object: seed.Object || [] },
            function (rel, fromId, toId, farId) {
                if (!fromId || !toId || fromId === toId) return;
                var unit = ix.unitOf[farId === toId ? fromId : toId];
                if (!unit) return;
                var dir = farId === toId ? 'out' : 'in';
                var type = rel.relationship_type || 'related-to';
                var farUnit = ix.unitOf[farId];
                if (farUnit === unit) return;
                if (farUnit) return note(unit, farUnit.id, 'claim', type, dir);
                if (ix.record[farId]) return note(unit, farId, 'claim', type, dir);
                var f = kit.relationshipFarEnd(rel, farId);
                if (!f) return;
                note(unit, farId, 'claim', type, dir, f.type === 'event'
                    ? { type: 'event', name: 'event', label: f.record.info, event: f.record }
                    : f.type === 'cluster'
                    ? { type: 'cluster', name: (f.record.Galaxy || {}).name || f.record.type,
                        label: String(f.record.value), galaxy_type: f.record.type }
                    : { type: f.type, name: f.type === 'object' ? f.record.name : f.record.type,
                        label: f.type === 'object' ? leadValue(f.record, seed.ui_priorities) : String(f.record.value),
                        to_ids: !!f.record.to_ids, event: f.event });
            });

        var list = Object.keys(ends).map(function (k) { return ends[k]; });
        list.forEach(function (e) {
            e.count = Object.keys(e.units).length;
            // Something new before another sighting of the value, then by
            // how many occurrences reach it.
            e.rank = (e.occurrence ? 0 : 1000) + e.count * 10
                + (e.via.some(function (v) { return v.kind === 'reference'; }) ? 1 : 0);
        });
        list.sort(function (a, b) { return b.rank - a.rank; });
        return { units: ix.units, leadUnits: ix.units.filter(function (u) { return u.reasons.length; }), ends: list };
    }

    function markLeads(data, model) {
        var lead = {};
        model.leadUnits.forEach(function (u) { lead[u.id] = true; });
        data.nodes.forEach(function (n) { if (lead[n.id]) n.data.lead = true; });
        data.edges.forEach(function (e) {
            if (e.data && e.data.kind === 'occurrence' && lead[e.to]) e.data.lead = true;
        });
    }

    /* ── stories: the seed read per event ──────────────────── */
    function relCount(rec) {
        return ((rec && rec.Relationship) || []).length + ((rec && rec.RelationshipInbound) || []).length;
    }

    // What a reference end is called: an attribute by its value, an object by
    // its template.
    function nameIndex(seed) {
        var far = seed.far || {};
        var out = {};
        function attr(a) { out[a.uuid] = String(a.value == null ? '' : a.value); }
        function obj(o) { out[o.uuid] = o.name; (o.Attribute || []).forEach(attr); }
        (seed.Object || []).forEach(obj);
        (far.objects || []).forEach(obj);
        (seed.Attribute || []).forEach(attr);
        (far.attributes || []).forEach(attr);
        return out;
    }

    // One story per event: the roles the value plays there, what its
    // occurrences reach, and a line of context. Newest event first.
    function stories(seed) {
        var cards = seed.events || {};
        var byId = {}, order = [];
        function story(eid) {
            eid = String(eid);
            if (!byId[eid]) {
                byId[eid] = { id: eid, card: cards[eid] || null, roles: {}, roleOrder: [], count: 0,
                              links: [], claims: 0, notes: [], feeds: [], servers: [] };
                order.push(eid);
            }
            return byId[eid];
        }
        function addRole(st, key, label) {
            if (!st.roles[key]) { st.roles[key] = { label: label, n: 0 }; st.roleOrder.push(key); }
            st.roles[key].n++;
        }
        var unitEvent = {};
        (seed.Object || []).forEach(function (o) {
            var st = story(o.event_id);
            st.count++;
            unitEvent[o.uuid] = st;
            (o.Attribute || []).forEach(function (a) {
                unitEvent[a.uuid] = st;
                st.claims += relCount(a);
            });
            var rel = heldRelations(o);
            addRole(st, 'o:' + o.name + ':' + rel, { rel: rel, holder: o.name });
            st.claims += relCount(o);
        });
        (seed.Attribute || []).forEach(function (a) {
            var st = story(a.event_id);
            st.count++;
            unitEvent[a.uuid] = st;
            addRole(st, 'a:' + a.type, { rel: a.type, holder: null });
            st.claims += relCount(a);
            var c = String(a.comment || '').split('\n')[0].trim();
            if (c && st.notes.indexOf(c) < 0) st.notes.push(c);
        });
        var names = nameIndex(seed);
        function link(st, dir, rel, uuid) {
            var name = names[uuid] || '';
            var hit = st.links.filter(function (l) { return l.dir === dir && l.rel === rel && l.name === name; })[0];
            if (hit) { hit.n++; return; }
            st.links.push({ dir: dir, rel: rel, name: name, n: 1 });
        }
        (seed.references || []).forEach(function (r) {
            var rel = r.relationship_type || 'related-to';
            var from = unitEvent[r.object_uuid], to = unitEvent[r.referenced_uuid];
            if (from) link(from, 'out', rel, r.referenced_uuid);
            if (to && to !== from) link(to, 'in', rel, r.object_uuid);
        });
        var byUuid = {};
        order.forEach(function (id) { var c = byId[id].card; if (c && c.uuid) byUuid[c.uuid] = byId[id]; });
        (seed.Feed || []).forEach(function (f) {
            (f.event_uuids || []).forEach(function (u) { if (byUuid[u]) byUuid[u].feeds.push(f.name); });
        });
        (seed.Server || []).forEach(function (sv) {
            (sv.event_uuids || []).forEach(function (u) { if (byUuid[u]) byUuid[u].servers.push(sv.name); });
        });
        var list = order.map(function (id) { return byId[id]; });
        list.sort(function (a, b) {
            var da = (a.card && a.card.date) || '', db = (b.card && b.card.date) || '';
            return db < da ? -1 : db > da ? 1 : b.count - a.count;
        });
        return list;
    }

    /* ── the opening: one row per event ────────────────────── */
    var BY_EVENT_RULE = 'by-event';
    var FOLD_FROM = 3;

    function dataOf(node) {
        return (node && node.getData ? node.getData() : node) || {};
    }

    // The occurrences one event holds fold into one group beside it — all but
    // the leads, which stay free so what is worth following is never inside a
    // group.
    function byEventRule() {
        return {
            kind: 'custom', id: BY_EVENT_RULE, label: 'By event',
            description: 'Folds the occurrences one event holds into one group beside it, leads left free',
            enabled: true, minSize: FOLD_FROM,
            partition: function (view) {
                var out = new Map();
                view.nodes.forEach(function (n) {
                    if (view.groupOf(n)) return;
                    var d = dataOf(n);
                    if ((d.type !== 'object' && d.type !== 'attribute') || !d.occurrence_of || d.lead) return;
                    var ev = view.outNeighbours(n).filter(function (x) { return dataOf(x).type === 'event'; })[0];
                    if (ev) out.set(n.id, 'event:' + ev.id);
                });
                return out;
            }
        };
    }

    // The tree hangs rows in the order the value's edges come, so the
    // occurrences are put in story order: newest event first.
    function byEventOrder(seed, data) {
        var rank = {};
        stories(seed).forEach(function (st, i) { rank[st.id] = i; });
        var eventOf = {};
        (seed.Object || []).forEach(function (o) { eventOf['obj:' + o.uuid] = String(o.event_id); });
        (seed.Attribute || []).forEach(function (a) { eventOf['attr:' + a.uuid] = String(a.event_id); });
        function key(e) {
            if ((e.data || {}).kind !== 'occurrence') return 1e9;
            var r = rank[eventOf[e.to]];
            return r === undefined ? 1e8 : r;
        }
        var indexed = data.edges.map(function (e, i) { return [key(e), i, e]; });
        indexed.sort(function (a, b) { return a[0] - b[0] || a[1] - b[1]; });
        data.edges = indexed.map(function (x) { return x[2]; });
        return data;
    }

    var ROW_PX = 58;
    // The explorer's cards engage at a zoom of 0.8.
    var CARD_ZOOM = 0.82;

    function rowsOf(seed) {
        var far = seed.far || {};
        return Object.keys(seed.events || {}).length + (seed.Feed || []).length + (seed.Server || []).length +
            (seed.near || []).length + (far.objects || []).length + (far.attributes || []).length;
    }

    function openingLayout(seed, height) {
        return {
            type: 'tree', rootId: valueNodeId(seed.value.b64), horizontal: true, spacing: 'manual',
            siblingSpacing: Math.max(0.6, rowsOf(seed) * ROW_PX / (height || 900)),
            levelSpacing: 0.9
        };
    }


    // The slice as the explorer's payload, so the sidebar, the analyst panel
    // and the tag pivots read the records behind every node drawn from it.
    function payloadOf(seed) {
        var far = seed.far || {};
        return { Event: {
            Attribute: (seed.Attribute || []).concat(far.attributes || []),
            Object:    (seed.Object || []).concat(far.objects || []),
            Feed:      seed.Feed || [],
            Server:    seed.Server || []
        } };
    }

    /* ── pivots: more of a value's occurrences ─────────────── */
    function drawnUuids(graph) {
        var out = [];
        (graph ? graph.getMutableNodes() : []).forEach(function (n) {
            var d = n.getData() || {};
            if ((d.type === 'object' || d.type === 'attribute') && d.uuid) out.push(d.uuid);
        });
        return out.sort();
    }

    function facetOptions(counts, label) {
        return Object.keys(counts || {}).map(function (k) {
            return { label: label ? label(k) : k, value: k, count: counts[k] };
        }).sort(function (a, b) { return b.count - a.count; });
    }

    function occurrenceFacets(c) {
        return [
            { key: 'template', label: 'Object', type: 'multiselect',
              options: facetOptions(c.by_template, function (k) { return k === '' ? 'Not in an object' : k; }) },
            { key: 'org', label: 'Creator org', type: 'multiselect',
              options: (c.by_org || []).map(function (o) { return { label: o.name, value: String(o.id), count: o.count }; }) },
            { key: 'year', label: 'Year', type: 'multiselect',
              options: facetOptions(c.by_year).sort(function (a, b) { return b.value.localeCompare(a.value); }) }
        ];
    }

    function occurrencesPivot(kit, spec) {
        var cache = {};
        function body(nodes, narrowing, count) {
            narrowing = narrowing || {};
            return { values: spec.valuesOf(nodes), exclude: drawnUuids(kit.graph()),
                     template: narrowing.template || [], org: narrowing.org || [],
                     year: narrowing.year || [], count: count };
        }
        function ask(b, signal) {
            var key = JSON.stringify(b);
            if (!cache[key]) {
                cache[key] = kit.postJson('/values/graphOccurrences.json', b, signal).catch(function (err) {
                    delete cache[key];
                    throw err;
                });
            }
            return cache[key];
        }
        return {
            id:            spec.id,
            label:         spec.label,
            maxCandidates: PIVOT_BUDGET,
            appliesTo:     function (nodes) { return nodes.filter(spec.applies); },
            summarize: function (nodes, narrowing, ctx) {
                // A fetch lands the newest PIVOT_BUDGET, which is what the run is
                // judged on; `matched` is the whole set, which the value's rim
                // count shows.
                return ask(body(nodes, narrowing, true), ctx && ctx.signal).then(function (c) {
                    return { total: Math.min(c.total || 0, PIVOT_BUDGET), matched: c.total || 0,
                             facets: occurrenceFacets(c) };
                });
            },
            fetch: function (nodes, narrowing, ctx) {
                return ask(body(nodes, narrowing, false), ctx && ctx.signal).then(function (slice) {
                    var land = kit.landing();
                    landOccurrences(kit, land, slice, spec.holderOf(nodes), spec.kind);
                    return land.result();
                });
            }
        };
    }

    function isValueNode(n) {
        var d = n.getData() || {};
        return d.type === 'value';
    }

    function isAttributeNode(n) {
        var d = n.getData() || {};
        return d.type === 'attribute' && d.value !== undefined && d.value !== '';
    }

    function valuesOf(nodes) {
        var seen = {};
        nodes.forEach(function (n) { seen[String((n.getData() || {}).value)] = true; });
        return Object.keys(seen);
    }

    // Which selected node a landed unit holds the value of.
    function holderOf(nodes) {
        var byValue = {};
        nodes.forEach(function (n) { byValue[String((n.getData() || {}).value)] = n.id; });
        return function (unit) {
            var attrs = unit.Attribute ? unit.Attribute.filter(function (a) {
                return (unit.holds || []).indexOf(a.uuid) !== -1;
            }) : [unit];
            for (var i = 0; i < attrs.length; i++) {
                var a = attrs[i];
                var hit = byValue[String(a.value)] || byValue[String(a.value1)] || byValue[String(a.value2)];
                if (hit) return hit;
            }
            return null;
        };
    }

    function valuePivots(kit) {
        var more = occurrencesPivot(kit, {
            id: MORE_PIVOT, label: 'More occurrences', kind: 'occurrence',
            applies: isValueNode, valuesOf: valuesOf, holderOf: holderOf
        });
        var where = occurrencesPivot(kit, {
            id: WHERE_PIVOT, label: 'Where else this appears', kind: 'correlation',
            applies: isAttributeNode, valuesOf: valuesOf, holderOf: holderOf
        });
        var p = kit.pivots;
        return [more, where, p.feedEvents(), p.tags(), p.taggedEvents(), p.relatedClusters(),
                p.relatingClusters(), p.surroundings(), p.cardElements('ids'), p.cardElements('network'), p.cardElements('all'),
                p.enrich()].filter(Boolean);
    }

    /* ── options ───────────────────────────────────────────── */
    function openValue(baseurl, b64) {
        window.open(baseurl + '/values/view/' + encodeURIComponent(b64), '_blank', 'noopener');
    }

    function valueOptions(config) {
        return function (opts, kit, seed) {
            var E = window.MispPivotNodes.palette().edge;
            Object.assign(opts.render.edgeStyleMap, {
                occurrence:        { strokeColor: E.link, strokeWidth: 1.5, markerEnd: 'none' },
                'occurrence-lead': { strokeColor: E.linkStrong, strokeWidth: 2.25, markerEnd: 'none' },
                near:              { strokeColor: E.link, dashed: true, markerEnd: 'none' }
            });
            var edgeType = opts.render.edgeTypeAccessor;
            opts.render.edgeTypeAccessor = function (edge) {
                var d = edge.getData ? edge.getData() : null;
                return d && d.kind === 'occurrence' && d.lead ? 'occurrence-lead' : edgeType(edge);
            };
            opts.layout = openingLayout(seed.raw, config.containerEl && config.containerEl.clientHeight);
            // Too many rows to fit at a readable size: open where the cards
            // read, on the value, and leave the rest to the minimap.
            opts.render.minFitScale = CARD_ZOOM;
            opts.render.fitAnchor = valueNodeId(seed.raw.value.b64);
            // The tree places every node; the physics only settles it.
            opts.simulation.cooldownTime = 1000;
            // What is not drawn yet is the value's rim count, shown from the start.
            opts.pivotRimBadgeVisible = 'always';
            var rules = opts.UI.simplify.rules;
            var at = rules.findIndex(function (r) { return r.kind === 'landings'; });
            rules.splice(at + 1, 0, byEventRule());
            opts.UI.extraPanels = [kit.sharedPanel()];
            if (kit.eventHasAnalystData(payloadOf(seed.raw).Event)) opts.UI.extraPanels.push(kit.analystPanel());
            opts.UI.contextMenu.menuNode.menu.unshift({
                text:      'Open value page',
                iconClass: 'misp-icon misp-icon-value-intelligence misp-simple',
                visible:   function (el) {
                    var n = Array.isArray(el) ? (el.length === 1 ? el[0] : null) : el;
                    var d = n && n.getData ? n.getData() : null;
                    return !!d && d.type === 'value' && !d.centre;
                },
                onclick:   function (e, el) {
                    var n = Array.isArray(el) ? el[0] : el;
                    openValue(config.baseurl, n.getData().b64);
                }
            });
            var dbclick = opts.callbacks.onNodeDbclick;
            opts.callbacks.onNodeDbclick = function (e, node) {
                var d = node && node.getData ? node.getData() : null;
                if (d && d.type === 'value' && !d.centre) {
                    window.location.href = config.baseurl + '/values/view/' + encodeURIComponent(d.b64);
                    return;
                }
                dbclick(e, node);
            };
        };
    }

    // What is left of the value's occurrences sits on its rim, and shrinks as
    // they land.
    function rimCount(graph, seed) {
        var centre = valueNodeId(seed.raw.value.b64);
        var node = graph.getMutableNode && graph.getMutableNode(centre);
        if (!node || typeof node.setPotential !== 'function') return;
        var drawn = 0;
        graph.getMutableNodes().forEach(function (n) {
            if (dataOf(n).occurrence_of === centre) drawn++;
        });
        var m = (seed.raw.meta || {}).occurrences || {};
        node.setPotential(MORE_PIVOT, Math.max(0, (m.units || 0) - drawn));
    }

    function afterMount(config) {
        return function (graph, kit, seed) {
            rimCount(graph, seed);
            if (typeof graph.on === 'function' && graph.pivots) {
                var changed = function () {
                    graph.pivots.invalidate(MORE_PIVOT);
                    graph.pivots.invalidate(WHERE_PIVOT);
                    rimCount(graph, seed);
                };
                graph.on('nodeAdd', changed);
                graph.on('nodeRemove', changed);
            }
        };
    }

    function fetchSeed(baseurl, b64) {
        return fetch(baseurl + '/values/graph/' + encodeURIComponent(b64) + '.json', {
            credentials: 'same-origin',
            headers: { 'Accept': 'application/json' }
        }).then(function (r) {
            if (!r.ok) throw new Error('HTTP ' + r.status);
            return r.json();
        });
    }

    // config.seed: a seed already fetched (the peek's), drawn rather than
    // asked for again.
    function loadSeed(config) {
        return function (kit) {
            return (config.seed ? Promise.resolve(config.seed) : fetchSeed(config.baseurl, config.b64))
            .then(function (seed) {
                return { raw: seed, event: payloadOf(seed), data: byEventOrder(seed, graphData(seed, kit)) };
            });
        };
    }

    function host(config) {
        return {
            containerEl: config.containerEl,
            loaderEl:    config.loaderEl,
            fitHeight:   false,
            provenance:  false,
            config: {
                baseurl:   config.baseurl,
                labelPlan: config.labelPlan,
                permitted: config.permitted,
                orgUuid:   config.orgUuid,
                siteAdmin: config.siteAdmin,
                valueCard: config.valueCard,
                canEnrich: config.canEnrich,
                text:      config.text
            },
            load:       loadSeed(config),
            pivots:     valuePivots,
            options:    valueOptions(config),
            afterMount: afterMount(config)
        };
    }

    function explorer(config) {
        return window.MispPivotExplorer.create(host(config));
    }

    window.MispValueNeighbourhood = {
        explorer:  explorer,
        fetchSeed:     fetchSeed,
        host:      host,
        graphData:     graphData,
        payloadOf:     payloadOf,
        valueNodeId:   valueNodeId,
        nearLabel:     nearLabel,
        leads:         leads,
        stories:       stories,
        byEventRule:   byEventRule,
        byEventOrder:  byEventOrder,
        openingLayout: openingLayout
    };
}());
