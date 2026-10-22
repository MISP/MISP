// Analyst Graph — a stored analyst graph drawn by the Pivot Explorer, its
// third host after the event page and the value Neighbourhood.
//
// The graph's `data` payload (/analyst_graphs/data/<uuid>.json) holds the
// document, the records of the nodes the viewer may read, shaped as the
// explorer's builders read them, and the edges MISP holds between them. This
// file turns it into pivotick data, and reads the document back off the
// canvas for a save.
//
//   MispAnalystGraph.mount(config)   → handle, the graph drawn into config.containerEl
//   MispAnalystGraph.graphData(payload, kit)
//
// config: { graph (uuid), containerEl, loaderEl?, payload?, request, baseurl,
//           labelPlan?, permitted?, orgUuid?, siteAdmin?, valueCard?, canEnrich?, text?,
//           ui?, canEdit?, canAnalyst?, analystSharing?, menus?, onChange?,
//           fitHeight?, cardEl? }
// request(method, path, body) → Promise<data> is IntelGraph's.
// ui: Pivotick UI options laid over the explorer's, key by key — a container
// smaller than a page asks for less chrome ({ mode: 'light' }, { legend: false }).
// canEdit, canAnalyst, analystSharing: the explorer's write tools, for a graph
// the user may edit. A reference can only be drawn inside an event the user
// may modify (data's editable_events); anything else is a relationship.
// menus: true adds "Keep in graph", "Remove from graph" and "Hide in this
// graph" to the canvas menus. onChange(handle) hears every edit a save keeps.
// saveControls: { save() → Promise }, the page's save: the canvas then
// carries a Save pill, and "Save as new graph…" for a user with graphSharing.
//
// Loaded by IntelGraph.load(), after pivotick.iife, misp-pivot-nodes, the
// sidebar and pivot-explorer.

(function () {
    'use strict';

    var ID_PREFIX = { Event: 'event:', Object: 'obj:', Attribute: 'attr:' };

    function lower(uuid) {
        return String(uuid || '').toLowerCase();
    }

    // A Value node is named by the SHA-256 of its text, every other node by its uuid
    function addressOf(node) {
        return lower(node.type === 'Value' ? node.sha256 : node.uuid);
    }

    function nodeKey(node) {
        return node.type + ':' + addressOf(node);
    }

    function valueNodeData(v) {
        return {
            type:        'value',
            label:       v.value,
            value:       v.value,
            b64:         v.b64,
            sha256:      v.sha256,
            description: 'Value',
            near_label:  'Value'
        };
    }

    function byUuid(list, field) {
        var out = {};
        (list || []).forEach(function (r) { out[lower(r[field || 'uuid'])] = r; });
        return out;
    }

    function hasPosition(n) {
        return typeof n.x === 'number' && typeof n.y === 'number';
    }

    // A stored note as pivotick's note options. An anchor no longer drawn
    // leaves the note where it was saved.
    function noteOptions(n, nodeId, edgeDrawn) {
        var note = {
            id: n.id, content: n.content, x: n.x, y: n.y,
            width: n.width, height: n.height, color: n.color, surface: n.surface
        };
        var id = n.node && nodeId(n.node);
        if (id) note.attachedElement = { type: 'node', id: id };
        else if (n.edge && edgeDrawn(n.edge)) note.attachedElement = { type: 'edge', id: n.edge };
        return note;
    }

    // The payload as pivotick data, and how its ids map onto the document.
    function graphData(payload, kit) {
        var land = kit.landing();
        var doc = payload.document || { nodes: [] };
        var cards = payload.events || {};
        var cardByUuid = {};
        Object.keys(cards).forEach(function (id) { cardByUuid[lower(cards[id].uuid)] = cards[id]; });
        var objects = byUuid(payload.Object);
        var attributes = byUuid(payload.Attribute);
        var clusters = byUuid(payload.GalaxyCluster);
        var values = byUuid(payload.Value, 'sha256');
        kit.mergePriorities(payload.ui_priorities);
        // An answer claims who kept it: the graph's organisation
        var keptBy = (payload.Graph && payload.Graph.Orgc && payload.Graph.Orgc.name) || null;
        var known = payload.known_values || [];

        function owner(rec) {
            var card = cards[rec.event_id] || {};
            return kit.provenance(rec.event_id, card.uuid);
        }

        // The objects drawn, so an attribute node inside one is drawn as its
        // child rather than a second node of the same id.
        var drawnObject = {};
        var parentOf = {};
        doc.nodes.forEach(function (n) {
            if (n.type !== 'Object' || !objects[lower(n.uuid)]) return;
            var obj = objects[lower(n.uuid)];
            drawnObject[lower(obj.uuid)] = kit.foreignObjectNode(obj, owner(obj));
            (obj.Attribute || []).forEach(function (a) { parentOf[lower(a.uuid)] = 'obj:' + lower(obj.uuid); });
        });

        var idOf = {}, keyOf = {}, folded = {}, clusterIdOf = {}, valueIdOf = {}, answerIdOf = {};
        var positioned = 0, drawn = 0;
        doc.nodes.forEach(function (n) {
            var uuid = addressOf(n);
            var node = null;
            switch (n.type) {
                case 'Event':
                    if (cardByUuid[uuid]) node = kit.eventCardNode(cardByUuid[uuid]);
                    break;
                case 'Object':
                    node = drawnObject[uuid] || null;
                    break;
                case 'Attribute':
                    if (!attributes[uuid]) break;
                    if (parentOf[uuid]) {
                        var id = 'attr:' + uuid;
                        var parent = drawnObject[parentOf[uuid].slice(4)];
                        parent.children.forEach(function (c) {
                            if (c.id === id) c.data.graph_node = true;
                        });
                        idOf[nodeKey(n)] = id;
                        keyOf[id] = nodeKey(n);
                        folded[id] = parentOf[uuid];
                        return;
                    }
                    node = { id: 'attr:' + uuid, data: kit.attributeNodeData(attributes[uuid], owner(attributes[uuid])) };
                    break;
                case 'GalaxyCluster':
                    if (clusters[uuid]) {
                        node = kit.clusterNode('cluster:' + clusters[uuid].tag_name, clusters[uuid]);
                        clusterIdOf[uuid] = node.id;
                    }
                    break;
                case 'Value':
                    if (values[uuid]) {
                        node = { id: 'value:' + values[uuid].b64, data: valueNodeData(values[uuid]) };
                        valueIdOf[uuid] = node.id;
                    }
                    break;
                case 'ModuleAnswer':
                    node = kit.answerNode(n, keptBy, known);
                    answerIdOf[uuid] = node.id;
                    break;
            }
            if (!node) return;
            node.data.graph_node = true;
            if (hasPosition(n)) {
                node.x = n.x;
                node.y = n.y;
                positioned++;
                if (n.pinned) {
                    node.fx = n.x;
                    node.fy = n.y;
                }
            }
            drawn++;
            land.node(node);
            idOf[nodeKey(n)] = node.id;
            keyOf[node.id] = nodeKey(n);
        });

        function endId(end) {
            var at = end.indexOf(':');
            var type = end.slice(0, at), uuid = lower(end.slice(at + 1));
            if (ID_PREFIX[type]) return ID_PREFIX[type] + uuid;
            if (type === 'GalaxyCluster') return clusterIdOf[uuid] || null;
            if (type === 'Value') return valueIdOf[uuid] || null;
            if (type === 'ModuleAnswer') return answerIdOf[uuid] || null;
            return null;
        }

        var hidden = {};
        (doc.hidden_edges || []).forEach(function (id) { hidden[id] = true; });
        // The edges the document hides, as they would be drawn: what a
        // "show it again" lands.
        var hiddenEdges = [];
        (payload.edges || []).forEach(function (e) {
            var edge = kit.storedEdge(e, endId);
            if (!edge) return;
            if (hidden[e.id]) hiddenEdges.push(edge);
            else land.edge(edge);
        });

        var out = land.result();
        var drawnEdge = {};
        out.edges.forEach(function (e) { drawnEdge[e.id] = true; });
        out.notes = (doc.notes || []).map(function (n) {
            return noteOptions(n, function (key) { return idOf[key]; }, function (id) { return drawnEdge[id]; });
        });
        return {
            data: out,
            idOf: idOf,
            keyOf: keyOf,
            folded: folded,
            hiddenEdges: hiddenEdges,
            // Every node drawn sits where it was saved: open it as it was left.
            positioned: drawn > 0 && positioned === drawn
        };
    }

    // The records as the explorer's payload, so the sidebar and the pivots
    // read the record behind every node.
    function payloadOf(payload) {
        return { Event: { Attribute: payload.Attribute || [], Object: payload.Object || [] } };
    }

    // A node brought onto the canvas, as the document names it.
    function documentNode(node) {
        var d = node.getData() || {};
        var at = node.id.indexOf(':');
        var prefix = node.id.slice(0, at + 1);
        if (prefix === 'event:') return { type: 'Event', uuid: lower(d.uuid || node.id.slice(at + 1)) };
        if (prefix === 'obj:') return { type: 'Object', uuid: lower(d.uuid || node.id.slice(at + 1)) };
        if (prefix === 'attr:') return { type: 'Attribute', uuid: lower(d.uuid || node.id.slice(at + 1)) };
        if (prefix === 'cluster:' && d.uuid) return { type: 'GalaxyCluster', uuid: lower(d.uuid) };
        if (prefix === 'value:' && d.value != null) return { type: 'Value', value: String(d.value) };
        return null;
    }

    // Keeps the nodes already drawn where they are while new ones find their
    // place, then lets go of those the analyst had not pinned. Without it an
    // add re-runs the layout and moves the saved one.
    function holdLayout(g) {
        holdNodes(g, g.getMutableNodes());
    }

    function holdNodes(g, nodes) {
        var held = [];
        nodes.forEach(function (n) {
            if (n.frozen || typeof n.x !== 'number' || typeof n.y !== 'number') return;
            n.fx = n.x;
            n.fy = n.y;
            held.push(n);
        });
        var start = Date.now();
        // Once the simulation has stopped: any heat left moves them.
        function release() {
            var sim = g.simulation && g.simulation.simulation;
            var alpha = sim && typeof sim.alpha === 'function' ? sim.alpha() : 0;
            var floor = sim && typeof sim.alphaMin === 'function' ? sim.alphaMin() : 0.001;
            if (alpha >= floor && Date.now() - start < 10000) {
                setTimeout(release, 200);
                return;
            }
            held.forEach(function (n) {
                if (n.frozen) return;
                n.fx = undefined;
                n.fy = undefined;
            });
        }
        setTimeout(release, 600);
    }

    // Beside a node it links to, or in the middle of what is on screen.
    function seedPosition(g, node, edges) {
        if (typeof node.x === 'number' && typeof node.y === 'number') return;
        var anchor = null;
        edges.some(function (e) {
            var other = e.from === node.id ? e.to : e.to === node.id ? e.from : null;
            var n = other && g.getMutableNode(other);
            if (n && typeof n.x === 'number') anchor = n;
            return !!anchor;
        });
        var at = anchor ? { x: anchor.x, y: anchor.y } : null;
        if (!at) {
            try {
                var svg = g.renderer.getCanvasSelection().node();
                var r = svg.getBoundingClientRect();
                at = g.renderer.screenToGraphCoordinates(r.left + r.width / 2, r.top + r.height / 2);
            } catch (e) {
                at = { x: 0, y: 0 };
            }
        }
        node.x = at.x + (Math.random() - 0.5) * 120;
        node.y = at.y + (Math.random() - 0.5) * 120;
    }

    function mount(config) {
        var state = {
            uuid: lower(config.graph),
            payload: null,
            built: null,
            revision: null,
            kept: [],
            // Since the last save: document keys taken off the canvas, and
            // edges hidden (true) or shown again (false).
            removed: {},
            hide: {},
            hiddenRaw: {},
            // The stored group each hand-made canvas group was restored from
            // or saved as, by canvas group id.
            groupOf: {},
            grouping: null,
            // The canvas's notes as last saved or loaded, and the stored
            // notes deleted since.
            notes: null,
            droppedNotes: {},
            placing: false,
            saving: false,
            dirty: false
        };
        var request = config.request;
        var explorer = null;
        var editableEvents = {};

        function fetchData() {
            return request('GET', '/analyst_graphs/data/' + encodeURIComponent(state.uuid) + '.json');
        }

        function take(payload, kit) {
            state.payload = payload;
            state.built = graphData(payload, kit);
            editableEvents = {};
            (payload.editable_events || []).forEach(function (id) { editableEvents[String(id)] = true; });
            return state.built;
        }

        function load(kit) {
            var first = config.payload ? Promise.resolve(config.payload) : fetchData();
            return first.then(function (payload) {
                take(payload, kit);
                state.revision = payload.Graph.revision;
                return { raw: payload, event: payloadOf(payload), data: state.built.data };
            });
        }

        function canEditGraph() {
            return !!(state.payload && state.payload.Graph._canEdit);
        }

        function changed(reason) {
            state.dirty = true;
            if (config.onChange) config.onChange(handle, reason);
            refreshControls();
        }

        // The pill re-reads itself once its own save settles; a refresh while
        // that save is out would leave it busy.
        function refreshControls() {
            var g = graph();
            if (!config.saveControls || state.saving || !g) return;
            try { g.UIManager.refreshTopBar(); } catch (e) { /* no top bar */ }
        }

        function nodesOf(element) {
            return (Array.isArray(element) ? element : [element]).filter(function (n) {
                return n && typeof n.getData === 'function';
            });
        }

        // A node as the document would hold it: a module answer whole, with
        // the origins the enrichment edges that landed it name.
        function documentNodeOf(node) {
            var kit = explorer.kit;
            if (kit.isAnswerNode(node)) return kit.answerItem(node, graph());
            return documentNode(node);
        }

        // A node anchor is the node's key, or the node whole while it has
        // none: the server names it.
        function documentNote(note) {
            return explorer.kit.noteItem(note, function (node) {
                return state.built.keyOf[node.id] || documentNodeOf(node);
            });
        }

        // On the canvas but not in the document: a pivot brought it. An
        // object's attributes come and go with the object.
        function isPivoted(node) {
            return !node.isChild && !state.built.keyOf[node.id] && state.kept.indexOf(node.id) === -1 && !!documentNodeOf(node);
        }

        // A stored answer is named by its key; a new one has none until saved.
        function storedAnswerRef(node) {
            var key = state.built.keyOf[node.id];
            return key && key.indexOf('ModuleAnswer:') === 0 ? { type: 'ModuleAnswer', uuid: key.slice(13) } : null;
        }

        function inDocument(node) {
            return !node.isChild && (!!state.built.keyOf[node.id] || state.kept.indexOf(node.id) !== -1);
        }

        function addMenus(opts) {
            var menu = opts.UI.contextMenu = opts.UI.contextMenu || {};
            function entries(section) {
                menu[section] = menu[section] || {};
                menu[section].menu = menu[section].menu || [];
                return menu[section].menu;
            }
            var keepEntry = function (text) {
                return {
                    text: text,
                    iconClass: 'fas fa-thumbtack',
                    visible: function (el) { return canEditGraph() && nodesOf(el).some(isPivoted); },
                    onclick: function (e, el) {
                        keep(nodesOf(el).filter(isPivoted).map(function (n) { return n.id; }));
                    }
                };
            };
            var removeEntry = function (text) {
                return {
                    text: text,
                    iconClass: 'fas fa-circle-minus',
                    visible: function (el) { return canEditGraph() && nodesOf(el).some(inDocument); },
                    onclick: function (e, el) {
                        remove(nodesOf(el).filter(inDocument).map(function (n) { return n.id; }));
                    }
                };
            };
            entries('menuNode').push(keepEntry('Keep in graph'), removeEntry('Remove from graph'));
            entries('menuSelection').push(keepEntry('Keep selection in graph'), removeEntry('Remove selection from graph'));
            entries('menuEdge').push({
                text: 'Hide in this graph',
                iconClass: 'fas fa-eye-slash',
                visible: function (el) { return canEditGraph() && !!(el && el.id); },
                onclick: function (e, el) { hideEdge(el.id); }
            });
        }

        function options(opts, kit, seed) {
            Object.assign(opts.render.edgeStyleMap, {
                value: { strokeColor: window.MispPivotNodes.palette().edge.link, dashed: true, markerEnd: 'none' }
            });
            if (state.built.positioned) {
                opts.simulation.warmupTicks = 0;
                opts.simulation.d3Alpha = 0.05;
            }
            var rules = (state.payload.document.view || {}).rules || {};
            ((opts.UI.simplify && opts.UI.simplify.rules) || []).forEach(function (r) {
                var id = r.id || r.kind;
                if (typeof rules[id] === 'boolean') r.enabled = rules[id];
            });
            opts.UI.extraPanels = [kit.sharedPanel()];
            if (!canEditGraph() && opts.UI.editors) {
                opts.UI.editors.edgeCreator = { enabled: false };
                opts.UI.editors.deletion = { enabled: false };
            }
            if (config.menus) addMenus(opts);
            if (config.ui) Object.assign(opts.UI, config.ui);
            var dbclick = opts.callbacks.onNodeDbclick;
            opts.callbacks.onNodeDbclick = function (e, node) {
                var d = node && node.getData ? node.getData() : null;
                if (d && d.type === 'value') {
                    window.location.href = config.baseurl + '/values/view/' + encodeURIComponent(d.b64);
                    return;
                }
                dbclick(e, node);
            };
        }

        // The stored groups become the canvas's hand-made groups, sitting and
        // open as saved; nodes pulled out of an auto group stay out.
        function restoreGrouping(g) {
            var simplify = g.simplify;
            var doc = state.payload.document;
            var built = state.built;
            state.groupOf = {};
            if (!simplify || !simplify.isEnabled()) return;
            function drawnId(key) {
                var id = built.idOf[key];
                return id && !built.folded[id] && g.getMutableNode(id) ? id : null;
            }
            var pulled = doc.nodes.filter(function (n) { return n.pulled_out; })
                .map(function (n) { return drawnId(nodeKey(n)); }).filter(Boolean);
            if (pulled.length) simplify.pullOut(pulled);
            var records = [];
            state.unrestored = [];
            (doc.groups || []).forEach(function (group, i) {
                var members = (group.members || []).map(drawnId).filter(Boolean);
                if (members.length < 2) {
                    state.unrestored.push(group);
                    return;
                }
                var record = { id: 'pvt-manual-' + (i + 1), members: members };
                if (group.title) record.title = group.title;
                state.groupOf[record.id] = group;
                records.push(record);
            });
            if (records.length) {
                simplify.setManualGroups(records);
                var placed = [];
                records.forEach(function (record) {
                    var group = state.groupOf[record.id];
                    var node = simplify.getGroupNode(record.id);
                    if (!node) return;
                    if (typeof group.x === 'number' && typeof group.y === 'number') {
                        node.x = group.x;
                        node.y = group.y;
                        placed.push(node);
                    }
                    if (group.open) simplify.open(record.id);
                });
                // A group is never pinned: held, it settles where it was saved.
                holdNodes(g, placed);
                g.nextTick();
            }
            state.grouping = groupingSignature();
            // Every grouping edit redraws; a retitle changes no dot, so the
            // grouping's own onChange misses it.
            g.onVisibleChange(function () {
                if (state.saving) return;
                var now = groupingSignature();
                if (now === state.grouping) return;
                state.grouping = now;
                changed('grouped');
            });
        }

        // What a save keeps of the grouping, positions aside: a drag is
        // already "moved".
        function groupingSignature() {
            var grouping = explorer.kit.canvasGrouping(inDocument, storedAnswerRef);
            return JSON.stringify([
                grouping.groups.map(function (group) {
                    return JSON.stringify([group.title || '', group.members.map(JSON.stringify).sort(), !!group.open]);
                }).sort(),
                grouping.rules,
                Object.keys(grouping.pulledOut).filter(function (id) {
                    var n = graph().getMutableNode(id);
                    return n && inDocument(n);
                }).sort()
            ]);
        }

        // What a save keeps of the notes.
        function notesSignature() {
            return JSON.stringify(graph().getNotes());
        }

        function watchNotes(g) {
            state.notes = notesSignature();
            ['noteAdd', 'noteChange', 'noteRemove'].forEach(function (name) {
                g.on(name, function (note) {
                    if (name === 'noteRemove') state.droppedNotes[note.id] = true;
                    else delete state.droppedNotes[note.id];
                    var now = notesSignature();
                    if (state.placing || now === state.notes) return;
                    state.notes = now;
                    changed('noted');
                });
            });
        }

        function afterMount(graph) {
            state.payload.document.nodes.forEach(function (n) {
                if (!n.pinned) return;
                var id = state.built.idOf[nodeKey(n)];
                var node = id && !state.built.folded[id] ? graph.getMutableNode(id) : null;
                if (node) node.freeze();
            });
            restoreGrouping(graph);
            watchNotes(graph);
            // A click ends a drag too; only one that moved the node counts.
            try {
                var bus = graph.renderer.getGraphInteraction();
                var dragged = false;
                bus.on('dragging', function () { dragged = true; });
                bus.on('dragended', function () {
                    if (dragged) changed('moved');
                    dragged = false;
                });
            } catch (e) { /* no interaction bus: moves go unnoticed */ }
        }

        // A reference stays inside one event, which the user must be able to
        // modify; anything else drawn becomes an analyst relationship.
        function canReference(from, to) {
            return !!from && !!to && from.event_id != null && editableEvents[String(from.event_id)]
                && String(from.event_id) === String(to.event_id);
        }

        explorer = window.MispPivotExplorer.create({
            containerEl: config.containerEl,
            loaderEl:    config.loaderEl || null,
            cardEl:      config.cardEl || null,
            fitHeight:   config.fitHeight === true,
            provenance:  false,
            config: {
                baseurl:        config.baseurl,
                labelPlan:      config.labelPlan,
                permitted:      config.permitted,
                orgUuid:        config.orgUuid,
                siteAdmin:      config.siteAdmin,
                valueCard:      config.valueCard,
                canEnrich:      config.canEnrich,
                canEdit:        !!config.canEdit,
                canAnalyst:     !!config.canAnalyst,
                analystSharing: config.analystSharing,
                graphSharing:   config.saveControls ? config.graphSharing : null,
                text:           config.text
            },
            load: load,
            graphUuid: function () { return state.uuid; },
            graphTarget: function () {
                var g = state.payload && state.payload.Graph;
                return g && g.object_uuid ? { type: g.object_type, uuid: g.object_uuid, label: g.name } : null;
            },
            savedGraph: config.saveControls ? {
                name:  function () { return (state.payload && state.payload.Graph.name) || ''; },
                dirty: function () { return canEditGraph() && state.dirty; },
                save:  config.saveControls.save
            } : null,
            pivots: function (kit) {
                var p = kit.pivots;
                return [p.tags(), p.taggedEvents(), p.relatedClusters(), p.relatingClusters(),
                        p.surroundings(),
                        p.cardElements('ids'), p.cardElements('network'), p.cardElements('all'),
                        p.enrich()].filter(Boolean);
            },
            options: options,
            afterMount: afterMount,
            canReference: canReference
        });

        function graph() {
            return explorer.graph();
        }

        // The canvas's groups as the document keeps them. A group restored
        // from the document keeps the members this canvas does not draw; a
        // stored group too thin to draw keeps those, and its drawn members
        // no other group took.
        function groupsOf(grouping) {
            var g = graph();
            var built = state.built;
            function drawn(key) {
                var id = built.idOf[key];
                return !!id && !!g.getMutableNode(built.folded[id] || id);
            }
            function regrouped(key) {
                var info = g.simplify && g.simplify.groupOf(built.idOf[key]);
                return !!info && (info.rule === 'manual' || info.rule === 'landings');
            }
            var groups = [], byId = {}, unrestored = [];
            grouping.groups.forEach(function (group) {
                var out = Object.assign({}, group, { members: group.members.slice() });
                delete out.id;
                var stored = state.groupOf[group.id];
                if (stored) {
                    stored.members.forEach(function (key) {
                        if (typeof key === 'string' && !drawn(key)) out.members.push(key);
                    });
                }
                if (/^pvt-manual-/.test(group.id)) byId[group.id] = out;
                groups.push(out);
            });
            (state.unrestored || []).forEach(function (group) {
                var out = Object.assign({}, group, {
                    members: group.members.filter(function (key) { return !drawn(key) || !regrouped(key); })
                });
                unrestored.push(out);
                groups.push(out);
            });
            return { groups: groups, byId: byId, unrestored: unrestored };
        }

        // The document's nodes still on the canvas, where they now sit;
        // the ones not drawn, as stored; then what the user kept. With
        // `sizes`, each canvas node's share of the bytes is counted into it.
        function documentOf(sizes) {
            return composeDocument(sizes).document;
        }

        function composeDocument(sizes) {
            var g = graph();
            var doc = state.payload.document;
            var built = state.built;
            var grouping = explorer.kit.canvasGrouping(inDocument, storedAnswerRef);
            var nodes = [];
            var measured = sizes ? explorer.kit.size.measured : function () {};
            doc.nodes.forEach(function (n) {
                var id = built.idOf[nodeKey(n)];
                if (!id) {
                    nodes.push(n);
                    return;
                }
                var onCanvas = g.getMutableNode(built.folded[id] || id);
                if (!onCanvas) return;
                if (built.folded[id]) {
                    nodes.push(n);
                    measured(sizes, onCanvas, n);
                    return;
                }
                var out = Object.assign({}, n);
                delete out.pinned;
                delete out.pulled_out;
                var at = explorer.kit.canvasPosition(onCanvas);
                if (at) {
                    out.x = at.x;
                    out.y = at.y;
                }
                if (onCanvas.frozen) out.pinned = true;
                if (grouping.pulledOut[id]) out.pulled_out = true;
                nodes.push(out);
                measured(sizes, onCanvas, out);
            });
            var seen = {};
            nodes.forEach(function (n) { seen[n.type === 'Value' ? 'Value:' + n.value : nodeKey(n)] = true; });
            // A pivoted node a note hangs on is kept with it
            var kept = state.kept.concat(g.getNotes().map(function (note) {
                var at = note.getAttachedElement();
                var node = at && at.type === 'node' ? g.getMutableNode(at.id) : null;
                return node && isPivoted(node) ? node.id : null;
            }).filter(Boolean));
            kept.forEach(function (id) {
                var node = g.getMutableNode(id);
                var n = node && documentNodeOf(node);
                if (!n) return;
                // The server names an answer; its canvas id is unique meanwhile
                var key = n.type === 'Value' ? 'Value:' + n.value
                    : n.type === 'ModuleAnswer' ? 'ModuleAnswer=' + id
                    : nodeKey(n);
                if (seen[key]) return;
                seen[key] = true;
                var at = explorer.kit.canvasPosition(node);
                if (at) {
                    n.x = at.x;
                    n.y = at.y;
                }
                if (node.frozen) n.pinned = true;
                if (grouping.pulledOut[id]) n.pulled_out = true;
                nodes.push(n);
                measured(sizes, node, n);
            });
            var groups = groupsOf(grouping);
            var view = Object.assign({}, doc.view || {});
            delete view.rules;
            if (Object.keys(grouping.rules).length) view.rules = grouping.rules;
            var hidden = [];
            (doc.hidden_edges || []).forEach(function (id) {
                if (state.hide[id] !== false) hidden.push(id);
            });
            Object.keys(state.hide).forEach(function (id) {
                if (state.hide[id] && hidden.indexOf(id) === -1) hidden.push(id);
            });
            var out = {
                version: doc.version || 1,
                nodes: nodes,
                groups: groups.groups,
                hidden_edges: hidden,
                view: view
            };
            // The canvas's notes, then the stored ones it does not draw
            var notes = g.getNotes().map(documentNote);
            var drawnNote = {};
            notes.forEach(function (n) { drawnNote[n.id] = true; });
            (doc.notes || []).forEach(function (n) {
                if (!drawnNote[n.id] && !state.droppedNotes[n.id]) notes.push(n);
            });
            if (notes.length) out.notes = notes;
            return {
                document: out,
                groupOf: groups.byId,
                unrestored: groups.unrestored
            };
        }

        // Pivoted-in nodes join the document on the next save.
        function keep(ids) {
            var added = 0;
            ids.forEach(function (id) {
                if (state.kept.indexOf(id) === -1 && !state.built.keyOf[id]) {
                    state.kept.push(id);
                    added++;
                }
            });
            if (added) changed('kept');
        }

        function pivoted() {
            var g = graph();
            if (!g || !state.built) return [];
            return g.getMutableNodes().filter(isPivoted).map(function (n) { return n.id; });
        }

        // Off the canvas, and out of the document on the next save.
        function remove(ids) {
            var g = graph();
            var gone = 0;
            ids.forEach(function (id) {
                var key = state.built.keyOf[id];
                if (key) state.removed[key] = true;
                var at = state.kept.indexOf(id);
                if (at !== -1) state.kept.splice(at, 1);
                if (g.getMutableNode(id)) {
                    g.removeNode(id);
                    gone++;
                }
            });
            if (gone) changed('removed');
        }

        function hideEdge(id) {
            var g = graph();
            var edge = g && g.getMutableEdge(id);
            if (!edge) return;
            state.hiddenRaw[id] = { id: id, from: edge.from.id, to: edge.to.id, data: edge.getData() };
            state.hide[id] = true;
            g.removeEdge(id);
            changed('hidden');
        }

        function storedHidden(id) {
            return (state.payload.document.hidden_edges || []).indexOf(id) !== -1;
        }

        // The edges hidden in this graph, stored or since: { id, from, to, data }.
        function hiddenEdges() {
            var out = state.built.hiddenEdges.filter(function (e) { return state.hide[e.id] !== false; });
            Object.keys(state.hide).forEach(function (id) {
                if (state.hide[id] && !storedHidden(id) && state.hiddenRaw[id]) out.push(state.hiddenRaw[id]);
            });
            return out;
        }

        function showEdge(id) {
            var g = graph();
            var raw = state.hiddenRaw[id] || state.built.hiddenEdges.filter(function (e) { return e.id === id; })[0];
            if (storedHidden(id)) state.hide[id] = false;
            else delete state.hide[id];
            if (raw && !g.getMutableEdge(id) && g.getMutableNode(raw.from) && g.getMutableNode(raw.to)) g.addEdge(raw);
            changed('shown');
        }

        function edgeHidden(id) {
            return state.hide[id] === true || (storedHidden(id) && state.hide[id] !== false);
        }

        // Change the canvas in place to the payload's document: what it
        // gained is added beside what it links to, what it lost is removed,
        // everything else stays where it is. Resolves the ids added.
        function apply(payload) {
            var g = graph();
            var before = state.built;
            var after = take(payload, explorer.kit);
            var fresh = after.data.nodes.filter(function (n) {
                return !g.getMutableNode(n.id) && !state.removed[after.keyOf[n.id]];
            });
            if (fresh.length) holdLayout(g);
            fresh.forEach(function (n) {
                seedPosition(g, n, after.data.edges);
                g.addNode(n);
            });
            Object.keys(before.keyOf).forEach(function (id) {
                if (!after.keyOf[id] && !before.folded[id] && state.kept.indexOf(id) === -1 && g.getMutableNode(id)) {
                    g.removeNode(id);
                }
            });
            after.data.edges.concat(after.hiddenEdges).forEach(function (e) {
                if (edgeHidden(e.id)) return;
                if (!g.getMutableEdge(e.id) && g.getMutableNode(e.from) && g.getMutableNode(e.to)) g.addEdge(e);
            });
            // A note saved elsewhere joins the canvas; one deleted here stays gone
            var unseen = (payload.document.notes || []).filter(function (n) {
                return !g.getNote(n.id) && !state.droppedNotes[n.id];
            });
            if (unseen.length) {
                quietNotes(function () {
                    unseen.forEach(function (n) { g.addNote(canvasNoteOptions(n)); });
                });
            }
            if (fresh.length) {
                try {
                    if (g.simulation && g.simulation.isEnabled()) g.simulation.reheat(0.3);
                } catch (e) { /* no simulation */ }
            }
            return fresh.map(function (n) { return n.id; });
        }

        function refresh() {
            return fetchData().then(function (payload) {
                apply(payload);
                return handle;
            });
        }

        // After a 409: the newer stored version, with this canvas's positions
        // and edits laid over it, becomes the base of the next save.
        function rebase() {
            return fetchData().then(function (payload) {
                apply(payload);
                state.revision = payload.Graph.revision;
                return handle;
            });
        }

        function save() {
            var composed = composeDocument();
            state.saving = true;
            return request('POST', '/analyst_graphs/save/' + encodeURIComponent(state.uuid) + '.json',
                           { content: composed.document, revision: state.revision })
            .then(function (report) {
                state.revision = report.revision;
                state.kept = [];
                state.removed = {};
                state.hide = {};
                state.hiddenRaw = {};
                state.groupOf = composed.groupOf;
                state.unrestored = composed.unrestored;
                state.droppedNotes = {};
                state.dirty = false;
                return refresh().then(function () {
                    if (state.grouping !== null) state.grouping = groupingSignature();
                    if (state.notes !== null) state.notes = notesSignature();
                    state.saving = false;
                    return report;
                });
            }, function (err) {
                state.saving = false;
                throw err;
            });
        }

        // An add or a removal made to this graph elsewhere. The base revision
        // moves only when that change is the one right after it.
        function followed(report) {
            if (!report || !report.changed) return Promise.resolve(handle);
            return handle.ready.then(function () {
                if (report.revision === state.revision + 1) state.revision = report.revision;
                return refresh();
            });
        }

        // Moves the drawn nodes to where the document puts them, pinned as it
        // says, and holds them there while anything still settles.
        function place(doc) {
            var g = graph();
            doc.nodes.forEach(function (n) {
                if (!hasPosition(n)) return;
                var id = state.built.idOf[nodeKey(n)];
                var node = id && !state.built.folded[id] ? g.getMutableNode(id) : null;
                if (!node) return;
                node.x = n.x;
                node.y = n.y;
                if (n.pinned) node.freeze();
                else if (node.frozen) node.unfreeze();
            });
            placeNotes(g, doc);
            holdLayout(g);
            g.nextTick();
        }

        // The canvas's notes become the document's.
        function placeNotes(g, doc) {
            quietNotes(function () {
                g.setNotes((doc.notes || []).map(canvasNoteOptions));
            });
            state.droppedNotes = {};
        }

        // A note change the canvas did not make, which no save owes.
        function quietNotes(fn) {
            state.placing = true;
            try {
                fn();
            } finally {
                state.placing = false;
            }
            if (state.notes !== null) state.notes = notesSignature();
        }

        function canvasNoteOptions(n) {
            var g = graph();
            return noteOptions(n, function (key) {
                var id = state.built.idOf[key];
                return id && g.getMutableNode(id) ? id : null;
            }, function (id) { return !!g.getMutableEdge(id); });
        }

        // This graph saved whole elsewhere on the page. A canvas with no edits
        // of its own becomes the saved one; one with edits only gains and loses
        // nodes, and keeps its base so its own save meets the conflict.
        function adopt(report) {
            if (!report || !report.changed) return Promise.resolve(handle);
            return handle.ready.then(fetchData).then(function (payload) {
                apply(payload);
                if (!state.dirty) {
                    place(payload.document);
                    state.revision = payload.Graph.revision;
                }
                return handle;
            });
        }

        // The canvas node a report key (Type:uuid) is drawn as: an attribute
        // inside a drawn object is that object.
        function nodeOf(key) {
            var g = graph();
            if (!g || !state.built) return null;
            var at = String(key).indexOf(':');
            var id = state.built.idOf[String(key).slice(0, at) + ':' + lower(String(key).slice(at + 1))];
            if (!id) return null;
            return g.getMutableNode(state.built.folded[id] || id) || null;
        }

        var handle = {
            uuid:       function () { return state.uuid; },
            graph:      graph,
            kit:        function () { return explorer.kit; },
            payload:    function () { return state.payload; },
            canEdit:    canEditGraph,
            revision:   function () { return state.revision; },
            isDirty:    function () { return state.dirty; },
            documentOf: documentOf,
            // { document, sizes }: what a save would send, and each canvas node's bytes in it
            measure:    function () {
                var sizes = {};
                return { document: documentOf(sizes), sizes: sizes };
            },
            nodeOf:     nodeOf,
            keep:       keep,
            pivoted:    pivoted,
            remove:     remove,
            hideEdge:   hideEdge,
            showEdge:   showEdge,
            hiddenEdges: hiddenEdges,
            save:       save,
            refreshControls: refreshControls,
            refresh:    refresh,
            rebase:     rebase,
            followed:   followed,
            adopt:      adopt,
            destroy:   function () {
                var g = graph();
                if (g && typeof g.destroy === 'function') g.destroy();
                if (config.containerEl) config.containerEl.innerHTML = '';
            }
        };
        handle.ready = explorer.init().then(function (ok) {
            if (!ok) throw new Error('The graph could not be drawn.');
            return handle;
        });
        return handle;
    }

    window.MispAnalystGraph = {
        mount:     mount,
        graphData: graphData,
        payloadOf: payloadOf
    };
}());
