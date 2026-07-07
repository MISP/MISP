<?php
    $eventId = h($data['Event']['id'] ?? '');

    echo $this->element('genericElements/assetLoader', [
        'js'  => ['pivotick.iife'],
        'css' => ['pivotick'],
    ]);
?>

<div class="card shadow-sm mb-3">

    <!-- BODY -->
    <div class="position-relative">

        <!-- Loader -->
        <div id="pivot-explorer-loader" class="text-center py-5 text-muted">
            <div class="spinner-border spinner-border-sm me-2" role="status"></div>
            <?= h(__('Building graph…')) ?>
        </div>

        <!-- Graph container (revealed after fetch) -->
        <div id="pivot-explorer-graph"
             style="width:100%;height:72vh;min-height:480px;display:none;"></div>
    </div>
</div>

<script>
(function () {

    /* ── PHP data ──────────────────────────────────────────── */
    var eventId = <?= json_encode($eventId) ?>;
    var baseurl = <?= json_encode($baseurl ?? '') ?>;

    /* ── state ─────────────────────────────────────────────── */
    var _initialized = false;
    var _graph       = null;

    /* ── helpers ───────────────────────────────────────────── */
    function truncate(str, max) {
        str = String(str == null ? '' : str);
        return str.length > max ? str.substring(0, max - 1) + '…' : str;
    }

    // Drop null/undefined fields from node data: pivotick's filter builder
    // indexes every data value and calls `.length` on it, so a null/undefined
    // value (e.g. object_relation on an event-level attribute) crashes it.
    function compact(obj) {
        var out = {};
        for (var k in obj) {
            if (obj[k] != null) out[k] = obj[k];   // skips both null and undefined
        }
        return out;
    }

    // Screenshots and other pictures are stored as `attachment` attributes whose
    // value is an image filename — mirror MispAttribute::isImage() server-side.
    function isImageAttribute(attr) {
        if (!attr || attr.type !== 'attachment') return false;
        return /\.(jpe?g|png|gif|webp)$/i.test(String(attr.value == null ? '' : attr.value));
    }

    // Thumbnail served by AttributesController::viewPicture() (ACL-checked,
    // accepts the attribute UUID). The webp variant is generated at 400px
    // (vs 200px for png) and cached, so the framed picture stays crisp.
    function attributeImageUrl(attr) {
        return baseurl + '/attributes/viewPicture/' + attr.uuid + '/webp';
    }

    /* ── misp-iconify (webfont) integration ────────────────── */
    // Pivotick resolves the glyph AND its font from the icon class itself
    // (font-agnostically, off the computed `::before`) and simply skips any
    // class it can't resolve — so an attribute type without a dedicated icon
    // just shows the bare coloured chip. We only map a node to its class name.
    function nodeIconClass(node) {
        var d = (node && node.getData) ? node.getData() : null;
        if (!d) return undefined;
        if (d.type === 'attribute') {
            // Image attachments render as an embedded thumbnail (imagePath),
            // so leave the icon unset to let the picture take over.
            if (d.image) return undefined;
            return d['attr-type']
                ? 'misp-icon misp-icon-' + d['attr-type'] + ' misp-attributes'
                : undefined;
        }
        if (d.type === 'object') {
            return d.name
                ? 'misp-icon misp-icon-' + d.name + ' misp-objects-framed'
                : undefined;
        }
        if (d.type === 'event') {
            return 'misp-icon misp-icon-event misp-simple';
        }
        return undefined;
    }

    /* ── build pivotick nodes/edges from a MISP event ──────── */
    function buildGraphData(event) {
        var ev      = (event && event.Event) ? event.Event : {};
        var nodes   = [];
        var edges   = [];
        var nodeSet = {};   // id -> true (dedupe + existence check for edges)
        var edgeSet = {};   // key -> true (dedupe)

        function addNode(id, node) {
            if (nodeSet[id]) return;
            nodeSet[id] = true;
            nodes.push(node);
        }
        function addEdge(from, to, label) {
            if (!nodeSet[from] || !nodeSet[to]) return;   // only link existing nodes
            var key = from + ' ' + to + ' ' + (label || '');
            if (edgeSet[key]) return;
            edgeSet[key] = true;
            edges.push({ from: from, to: to, data: { label: label || '' } });
        }

        function attributeNodeData(attr) {
            var val   = attr.value != null ? String(attr.value) : '';
            var isImg = isImageAttribute(attr);
            return compact({
                type:            'attribute',
                label:           truncate(val, 42),
                description:     (attr.object_relation ? attr.object_relation + ' · ' : '')
                                 + (attr.category || '') + (attr.type ? ' / ' + attr.type : ''),
                value:           val,
                'attr-type':     attr.type,
                category:        attr.category,
                object_relation: attr.object_relation,
                to_ids:          attr.to_ids,
                comment:         attr.comment,
                uuid:            attr.uuid,
                image:           isImg || undefined,
                imageUrl:        isImg ? attributeImageUrl(attr) : undefined
            });
        }

        // Register an attribute's id (dedupe + edge existence) and return its node
        // dict, or null if already added. The caller decides where to place it —
        // top-level (nodes) or nested inside an object (children).
        function buildAttributeNode(attr) {
            var id = 'attr:' + attr.uuid;
            if (nodeSet[id]) return null;
            nodeSet[id] = true;
            return { id: id, data: attributeNodeData(attr) };
        }

        // Top-level attribute node (used for event-level attributes).
        function addAttributeNode(attr) {
            var node = buildAttributeNode(attr);
            if (node) nodes.push(node);
            return 'attr:' + attr.uuid;
        }

        /* Event root node */
        // var eventNodeId = 'event:' + (ev.uuid || ev.id);
        // addNode(eventNodeId, {
        //     id: eventNodeId,
        //     data: {
        //         type:        'event',
        //         label:       truncate(ev.info || ('Event #' + ev.id), 60),
        //         description: 'Event #' + ev.id + (ev.date ? ' · ' + ev.date : ''),
        //         info:        ev.info,
        //         date:        ev.date,
        //         uuid:        ev.uuid
        //     }
        // });

        /* Which event-level attributes are pointed at by an object reference?
           (referenced_type 0 = attribute). These are the only standalone
           attributes worth showing — they anchor to the object graph rather
           than floating free, and this also covers referenced screenshots. */
        var referencedAttrUuids = {};
        (ev.Object || []).forEach(function (obj) {
            (obj.ObjectReference || []).forEach(function (ref) {
                if (String(ref.referenced_type) !== '1') {
                    referencedAttrUuids[ref.referenced_uuid] = true;
                }
            });
        });

        /* Event-level attributes: surfaced only when an object references them,
           so every node stays connected to the graph. */
        (ev.Attribute || []).forEach(function (attr) {
            if (referencedAttrUuids[attr.uuid]) {
                addAttributeNode(attr);
            }
        });

        /* Objects and their attributes (attributes nested inside the object) */
        (ev.Object || []).forEach(function (obj) {
            var objId = 'obj:' + obj.uuid;

            // Attributes are nested as children of their object rather than
            // linked by an edge — containment expresses the object/attribute
            // relationship (the object_relation is folded into the description).
            var children = [];
            (obj.Attribute || []).forEach(function (attr) {
                var child = buildAttributeNode(attr);
                if (child) children.push(child);
            });

            addNode(objId, {
                id:       objId,
                children: children,
                // expanded: children.length > 0,   // reveal nested attributes by default
                data: compact({
                    type:            'object',
                    label:           truncate(obj.name || 'Object', 42),
                    description:     obj['meta-category'] ? (obj['meta-category'] + ' object') : 'Object',
                    name:            obj.name,
                    'meta-category': obj['meta-category'],
                    uuid:            obj.uuid
                })
            });
            // addEdge(eventNodeId, objId, ''); // Do not add fake edge to the event
        });

        /* Object references (added last so both ends already exist) */
        (ev.Object || []).forEach(function (obj) {
            var objId = 'obj:' + obj.uuid;
            (obj.ObjectReference || []).forEach(function (ref) {
                var prefix   = (String(ref.referenced_type) === '1') ? 'obj:' : 'attr:';
                var targetId = prefix + ref.referenced_uuid;
                addEdge(objId, targetId, ref.relationship_type || 'related-to');
            });
        });

        return { nodes: nodes, edges: edges };
    }

    /* ── pivotick options ──────────────────────────────────── */
    function graphOptions() {
        return {
            isDirected: true,
            render: {
                type: 'svg',
                nodeTypeAccessor: function (node) {
                    var d = node.getData();
                    if (!d) return undefined;
                    return d.image ? 'image' : d.type;
                },
                nodeStyleMap: {
                    event:     { shape: 'hexagon', color: '#6fbe80', size: 26 },
                    object:    { shape: 'square',  color: '#428bca', size: 20 },
                    attribute: { shape: 'circle',  color: '#f39a1f', size: 13 },
                    image:     {
                        imageFit:    'frame',
                        size:        80,
                        strokeColor: 'rgba(255,255,255,0.55)',
                        strokeWidth: 2
                    }
                },
                defaultNodeStyle: {
                    // Labels are not drawn by default — render data.label above each node.
                    text: function (node) {
                        var d = node.getData();
                        return d ? d.label : '';
                    },
                    // Overlay a misp-iconify glyph on the coloured shape; pivotick
                    // resolves the glyph + "MISP Icons" font from the class itself.
                    iconClass: nodeIconClass,
                    // Image attachments (screenshots) draw an embedded thumbnail
                    // instead of a glyph — pivotick renders imagePath as an
                    // <image>, but only when iconClass is left unset (see above).
                    imagePath: function (node) {
                        var d = node.getData();
                        return (d && d.image) ? d.imageUrl : undefined;
                    },
                    // textColor: '#2b2f33',
                    textVerticalShift: -1
                }
            },
            simulation: {
                d3LinkDistance: 200
            },
            UI: {
                mode: 'full',
                theme: 'dark'
            }
        };
    }

    /* ── init ──────────────────────────────────────────────── */
    function initGraph() {
        if (_initialized) return;
        _initialized = true;

        var loaderEl    = document.getElementById('pivot-explorer-loader');
        var containerEl = document.getElementById('pivot-explorer-graph');

        if (typeof window.Pivotick !== 'function') {
            if (loaderEl) loaderEl.innerHTML =
                '<p class="text-danger mb-0"><i class="fas fa-exclamation-triangle me-2"></i>'
                + <?= json_encode(h(__('Graph library failed to load.'))) ?> + '</p>';
            return;
        }

        fetch(baseurl + '/events/view/' + eventId + '.json', { credentials: 'same-origin' })
            .then(function (r) {
                if (!r.ok) throw new Error(r.status);
                return r.json();
            })
            .then(function (event) {
                var data = buildGraphData(event);

                if (loaderEl)    loaderEl.style.display    = 'none';
                if (containerEl) containerEl.style.display = '';

                _graph = new window.Pivotick(containerEl, data, graphOptions());
            })
            .catch(function (err) {
                console.error('[pivot-explorer] graph build failed:', err);
                _initialized = false;   // allow a retry on the next tab activation
                if (loaderEl) loaderEl.innerHTML =
                    '<p class="text-danger mb-0"><i class="fas fa-exclamation-triangle me-2"></i>'
                    + <?= json_encode(h(__('Failed to load event graph.'))) ?> + '</p>';
            });
    }

    /* ── lazy-load when the tab becomes visible ────────────── */
    document.addEventListener('shown.bs.tab', function (e) {
        if (e.target && e.target.getAttribute('href') === '#tab-pivot-explorer') {
            initGraph();
        }
    });

    var pane = document.getElementById('tab-pivot-explorer');
    if (pane && pane.classList.contains('active')) {
        initGraph();
    }

}());
</script>
