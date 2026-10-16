// Cluster Pivot Explorer — a galaxy cluster drawn with what MISP links it
// to: the clusters its galaxy relations join it to, both ways, and its
// analyst relationships, an attribute or object at the far end beside its
// event's card.
//
// Built on window.MispPivotExplorer (pivot-explorer.js): this file is the
// cluster's host — its seed, its pivots and its options — and the
// explorer's builders do the drawing. The element
// (Elements/GalaxyClusters/View/galaxy_cluster_pivot_explorer.ctp) owns the
// markup; its config is read off #cpe-card's data-* attributes.
//
//   MispClusterPivotExplorer.explorer(config)  the graph, into config.containerEl

(function () {
    'use strict';

    var ANALYST_PIVOT = 'cluster-relationships';

    function fetchSeed(baseurl, id, signal) {
        return fetch(baseurl + '/galaxy_clusters/graph/' + encodeURIComponent(id) + '.json', {
            credentials: 'same-origin',
            signal:      signal,
            headers:     { 'Accept': 'application/json' }
        }).then(function (r) {
            if (!r.ok) throw new Error('HTTP ' + r.status);
            return r.json();
        });
    }

    function dataOf(node) {
        return (node && node.getData ? node.getData() : node) || {};
    }

    // The analyst relationships on one cluster record, each far end drawn as
    // the explorer's seed draws another event's element.
    function landRelationships(kit, land, rec, selfId) {
        kit.eachRelationshipOn(rec, selfId, function (rel, fromId, toId, farId) {
            if (!fromId || !toId || fromId === toId) return;
            if (!land.get(farId)) {
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
            }
            var type = rel.relationship_type || 'related-to';
            land.edge({ id: 'analyst:' + rel.uuid, from: fromId, to: toId,
                        data: { kind: 'analyst-relationship', label: type, authors: rel.authors,
                                orgc: rel.orgc_uuid, uuid: rel.uuid, relationship_type: type } });
        });
    }

    function landRelations(kit, land, selfId, list, inbound) {
        (list || []).forEach(function (r) {
            var c = r.cluster || {};
            if (!c.tag_name || kit.clusterNodeId(c) === selfId) return;
            var id = land.node(kit.relatedClusterNode(c));
            land.edge(inbound ? kit.clusterRelationEdge(id, selfId, r.relation)
                              : kit.clusterRelationEdge(selfId, id, r.relation));
        });
    }

    // The seed as pivotick data: the cluster, its relations and its analyst
    // relationships.
    function graphData(seed, kit) {
        var land = kit.landing();
        var rec = seed.cluster;
        var centre = kit.clusterNode(kit.clusterNodeId(rec), rec);
        Object.assign(centre.data, kit.analystFields(rec), { centre: true });
        land.node(centre);
        landRelations(kit, land, centre.id, seed.outbound, false);
        landRelations(kit, land, centre.id, seed.inbound, true);
        landRelationships(kit, land, rec, centre.id);
        return land.result();
    }

    // The explorer reads its records out of an event payload; the cluster
    // rides beside it, so its notes and opinions reach the analyst panel.
    function payloadOf(seed) {
        return { Event: {}, records: [seed.cluster] };
    }

    /* ── pivot: a cluster's analyst relationships ──────────── */
    function relationshipCount(rec) {
        return (rec.Relationship || []).length + (rec.RelationshipInbound || []).length;
    }

    function relationshipsPivot(config, centreId) {
        var seeds = {};
        function seedOf(ref, signal) {
            if (!seeds[ref]) {
                seeds[ref] = fetchSeed(config.baseurl, ref, signal).catch(function (err) {
                    delete seeds[ref];
                    throw err;
                });
            }
            return seeds[ref];
        }
        function seedsOf(kit, nodes, signal) {
            return Promise.all(nodes.map(function (n) { return seedOf(kit.clusterRef(dataOf(n)), signal); }));
        }
        return function (kit) {
            return {
                id:            ANALYST_PIVOT,
                label:         'Analyst relationships',
                appliesTo: function (nodes) {
                    return nodes.filter(function (n) {
                        var d = dataOf(n);
                        return d.type === 'cluster' && !!kit.clusterRef(d) && n.id !== centreId();
                    });
                },
                summarize: function (nodes, narrowing, ctx) {
                    return seedsOf(kit, nodes, ctx && ctx.signal).then(function (list) {
                        return { total: list.reduce(function (s, seed) { return s + relationshipCount(seed.cluster); }, 0) };
                    });
                },
                fetch: function (nodes, narrowing, ctx) {
                    return seedsOf(kit, nodes, ctx && ctx.signal).then(function (list) {
                        var land = kit.landing();
                        nodes.forEach(function (n, i) { landRelationships(kit, land, list[i].cluster, n.id); });
                        return land.result();
                    });
                }
            };
        };
    }

    function clusterPivots(config, centreId) {
        var relationships = relationshipsPivot(config, centreId);
        return function (kit) {
            var p = kit.pivots;
            return [p.relatedClusters(), p.relatingClusters(), relationships(kit), p.taggedEvents(),
                    p.tags(), p.feedEvents(), p.surroundings(), p.cardElements('ids'),
                    p.cardElements('network'), p.cardElements('all'), p.enrich()].filter(Boolean);
        };
    }

    /* ── options ───────────────────────────────────────────── */
    function clusterOptions(config) {
        return function (opts, kit, seed) {
            var centre = kit.clusterNodeId(seed.raw.cluster);
            opts.render.fitAnchor = centre;
            opts.UI.extraPanels = [kit.sharedPanel()];
            if (kit.eventHasAnalystData(seed.raw.cluster)) opts.UI.extraPanels.push(kit.analystPanel());
            var dbclick = opts.callbacks.onNodeDbclick;
            opts.callbacks.onNodeDbclick = function (e, node) {
                var d = dataOf(node);
                if (d.type === 'cluster' && kit.clusterRef(d) && node.id !== centre) {
                    window.location.href = config.baseurl + '/galaxy_clusters/view/' + encodeURIComponent(kit.clusterRef(d));
                    return;
                }
                dbclick(e, node);
            };
        };
    }

    // A cluster with more relations than one seed draws says so.
    function afterMount(config) {
        return function (graph, kit, seed) {
            var raw = seed.raw;
            var left = Math.max(0, (raw.totals.outbound || 0) - raw.outbound.length)
                     + Math.max(0, (raw.totals.inbound || 0) - raw.inbound.length);
            if (left && graph.notifier) {
                graph.notifier.info(config.text.truncatedTitle,
                    config.text.truncated.replace('%s', String(raw.budget)));
            }
        };
    }

    function host(config) {
        var centre = null;
        var cluster = null;
        return {
            cardEl:      config.cardEl,
            containerEl: config.containerEl,
            loaderEl:    config.loaderEl,
            provenance:  false,
            links:       true,
            config: {
                baseurl:        config.baseurl,
                canAnalyst:     config.canAnalyst,
                analystSharing: config.analystSharing,
                graphSharing:   config.graphSharing,
                labelPlan:      config.labelPlan,
                permitted:      config.permitted,
                orgUuid:        config.orgUuid,
                siteAdmin:      config.siteAdmin,
                valueCard:      config.valueCard,
                canEnrich:      config.canEnrich,
                text:           config.text
            },
            load: function (kit) {
                return fetchSeed(config.baseurl, config.clusterId).then(function (seed) {
                    centre = kit.clusterNodeId(seed.cluster);
                    cluster = seed.cluster;
                    return { raw: seed, event: payloadOf(seed), data: graphData(seed, kit) };
                });
            },
            // "Save as graph" keeps the canvas on the cluster it started from.
            graphTarget: function () {
                return cluster && cluster.uuid
                    ? { type: 'GalaxyCluster', uuid: cluster.uuid, label: cluster.value || '' }
                    : null;
            },
            pivots:     clusterPivots(config, function () { return centre; }),
            options:    clusterOptions(config),
            afterMount: afterMount(config)
        };
    }

    function explorer(config) {
        return window.MispPivotExplorer.create(host(config));
    }

    function readJson(raw, fallback, what) {
        try {
            return JSON.parse(raw || fallback);
        } catch (e) {
            console.error('[cluster-pivot-explorer] unreadable ' + what + ':', e);
            return JSON.parse(fallback);
        }
    }

    /* ── boot ──────────────────────────────────────────────── */
    // Built once its tab is shown, like the event page's.
    function boot() {
        var cardEl = document.getElementById('cpe-card');
        if (!cardEl || !window.MispPivotExplorer) return;
        var d = cardEl.dataset;
        var graph = explorer({
            cardEl:         cardEl,
            loaderEl:       document.getElementById('cluster-pivot-explorer-loader'),
            containerEl:    document.getElementById('cluster-pivot-explorer-graph'),
            clusterId:      d.cpeClusterId || '',
            baseurl:        d.cpeBaseurl || '',
            canAnalyst:     d.cpeCanAnalyst === '1',
            analystSharing: readJson(d.cpeAnalystSharing, '{}', 'analyst sharing options'),
            graphSharing:   readJson(d.cpeGraphSharing, 'null', 'graph sharing options'),
            labelPlan:      readJson(d.cpeLabelPlan, 'null', 'analyst profile priorities'),
            permitted:      readJson(d.cpePermitted, 'null', 'analyst profile priorities'),
            orgUuid:        d.cpeOrgUuid || '',
            siteAdmin:      d.cpeSiteAdmin === '1',
            valueCard:      d.cpeValueCard === '1',
            canEnrich:      d.cpeCanEnrich === '1',
            text: {
                libMissing:     d.cpeLibMissing || 'Graph library failed to load.',
                loadFailed:     d.cpeLoadFailed || 'Failed to load the cluster graph.',
                truncatedTitle: d.cpeTruncatedTitle || 'Not every relation is drawn',
                truncated:      d.cpeTruncated || 'The newest %s relations each way are on the canvas.'
            }
        });

        document.addEventListener('shown.bs.tab', function (e) {
            if (e.target && e.target.getAttribute('href') === '#tab-pivot-explorer') graph.init();
        });
        var pane = document.getElementById('tab-pivot-explorer');
        if (pane && pane.classList.contains('active')) graph.init();
    }

    window.MispClusterPivotExplorer = { explorer: explorer, host: host, graphData: graphData };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }
}());
