<?php
    $eventId  = h($data['Event']['id'] ?? '');
    // Editor chrome is only emitted when the viewer may modify the event
    // (same ACL the ObjectReferences add endpoint enforces server-side).
    $canEdit  = !empty($mayModify);

    echo $this->element('genericElements/assetLoader', [
        'js'  => ['pivotick.iife'],
        'css' => ['pivotick'],
    ]);
?>

<div class="card shadow-sm mb-3" id="pe-card">

    <!-- BODY -->
    <div class="position-relative" id="pe-stage">

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

<?php if ($canEdit): ?>
<style>
    /* The tray is rendered inside pivotick's sidebar (extraPanel); these style
       its contents. The relationship picker overlays the graph stage. */
    #pe-card .pe-tray-body { display: flex; flex-direction: column; gap: .5rem; font-size: .82rem; }
    #pe-card .pe-count { font-size: .74rem; opacity: .75; }
    #pe-card .pe-count .pe-badge {
        margin-left: .25rem; padding: 0 .45rem; border-radius: 999px;
        background: #f39a1f; color: #1a1d21; font-size: .72rem; font-weight: 700;
    }
    #pe-card .pe-filter {
        width: 100%; padding: .35rem .5rem; border-radius: 6px;
        border: 1px solid rgba(128,128,128,.35);
        background: rgba(128,128,128,.08); color: inherit; font-size: .82rem;
    }
    #pe-card .pe-tray-list { overflow-y: auto; max-height: 46vh; }
    #pe-card .pe-group-label {
        font-size: .68rem; text-transform: uppercase; letter-spacing: .04em;
        opacity: .5; margin: .5rem 0 .25rem;
    }
    #pe-card .pe-chip {
        display: flex; flex-direction: column; gap: 1px;
        padding: .35rem .5rem; margin-bottom: .3rem; border-radius: 6px;
        background: rgba(243,154,31,.12); border: 1px solid rgba(243,154,31,.35);
        cursor: grab; font-size: .8rem;
    }
    #pe-card .pe-chip:hover { background: rgba(243,154,31,.22); }
    #pe-card .pe-chip:active { cursor: grabbing; }
    #pe-card .pe-chip.pe-chip-staged { opacity: .4; cursor: default; }
    #pe-card .pe-chip-val { font-weight: 600; word-break: break-all; }
    #pe-card .pe-chip-meta { font-size: .68rem; opacity: .6; }
    /* Objects are blue (matching their canvas node), attributes orange. */
    #pe-card .pe-chip-object {
        background: rgba(66,139,202,.14); border-color: rgba(66,139,202,.45);
    }
    #pe-card .pe-chip-object:hover { background: rgba(66,139,202,.24); }
    #pe-card .pe-empty { font-size: .78rem; opacity: .5; padding: .5rem 0; }

    #pe-stage.pe-drop-active #pivot-explorer-graph { outline: 2px dashed #428bca; outline-offset: -4px; }

    /* Drag ghost — follows the cursor (appended to <body>, so unscoped). */
    .pe-ghost {
        position: fixed; z-index: 9999; pointer-events: none;
        padding: .25rem .55rem; border-radius: 6px;
        font-size: .76rem; font-weight: 600; white-space: nowrap;
        box-shadow: 0 4px 14px rgba(0,0,0,.4);
    }
    .pe-ghost-attribute { background: #f39a1f; color: #1a1d21; }
    .pe-ghost-object    { background: #428bca; color: #fff; }

    /* Relationship picker */
    #pe-card .pe-picker-backdrop {
        position: absolute; inset: 0; z-index: 40;
        background: rgba(0,0,0,.35); display: flex;
        align-items: center; justify-content: center;
    }
    #pe-card .pe-picker {
        width: 320px; max-width: 90%; padding: 1rem; border-radius: 10px;
        background: #1c2128; border: 1px solid rgba(255,255,255,.14);
        box-shadow: 0 12px 32px rgba(0,0,0,.5); color: #e6e8ea;
    }
    #pe-card .pe-picker h4 { font-size: .95rem; margin: 0 0 .25rem; }
    #pe-card .pe-picker .pe-picker-sub { font-size: .74rem; opacity: .6; margin-bottom: .75rem; word-break: break-all; }
    #pe-card .pe-picker label { display: block; font-size: .75rem; opacity: .7; margin: .5rem 0 .2rem; }
    #pe-card .pe-picker select,
    #pe-card .pe-picker input[type="text"] {
        width: 100%; padding: .4rem .5rem; border-radius: 6px;
        border: 1px solid rgba(255,255,255,.15); background: rgba(0,0,0,.25);
        color: inherit; font-size: .85rem;
    }
    #pe-card .pe-picker-btn {
        display: inline-flex; align-items: center; gap: .4rem;
        padding: .3rem .7rem; border-radius: 6px; cursor: pointer;
        border: 1px solid rgba(255,255,255,.18);
        background: rgba(255,255,255,.06); color: inherit; font-size: .85rem;
    }
    #pe-card .pe-picker-btn:hover { background: rgba(255,255,255,.12); }
    #pe-card .pe-picker-actions { display: flex; justify-content: flex-end; gap: .5rem; margin-top: 1rem; }
    #pe-card .pe-picker .pe-btn-primary { background: #428bca; border-color: #428bca; color: #fff; }
</style>
<?php endif; ?>

<script>
(function () {

    /* ── PHP data ──────────────────────────────────────────── */
    var eventId = <?= json_encode($eventId) ?>;
    var baseurl = <?= json_encode($baseurl ?? '') ?>;
    var canEdit = <?= $canEdit ? 'true' : 'false' ?>;

    /* ── state ─────────────────────────────────────────────── */
    var _initialized = false;
    var _graph       = null;
    var _event       = null;

    /* Common object-reference relationship types (misp-objects). The DB list
       is authoritative; this curated default keeps the prototype self-contained
       even when the object-relationship table is empty. relationship_type is
       free text server-side, so "custom…" always works. */
    var DEFAULT_RELATIONSHIPS = [
        'related-to', 'connected-to', 'includes', 'included-in', 'part-of',
        'derived-from', 'downloaded-from', 'downloads', 'dropped-by', 'drops',
        'communicates-with', 'resolves-to', 'mentions', 'mitigates', 'uses',
        'used-by', 'targets', 'beacons-to', 'contacts', 'characterizes',
        'indicates', 'references', 'variant-of', 'child-of', 'parent-of'
    ];

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

    // Shared by the graph builder and the editor's drop handler so a dragged-in
    // attribute renders identically to one that was referenced from the start.
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

    // Soft-deleted records (deleted=1) are tombstones — refs create no edge and
    // don't count a node as connected; deleted attributes/objects aren't shown.
    function isDeleted(rec) {
        return !!rec && (rec.deleted === true || rec.deleted === 1 || rec.deleted === '1');
    }

    // Single source of truth for "what is connected" — used by both the canvas
    // builder and the editor tray so they never disagree. An object counts as
    // connected if it is a reference source, an object-target, OR owns a child
    // attribute that some (live) reference points at.
    function computeConnectivity(ev) {
        var referencedAttrUuids = {};
        var connectedObjUuids   = {};
        var attrOwner           = {};   // object child attr uuid -> owning object uuid
        (ev.Object || []).forEach(function (obj) {
            (obj.Attribute || []).forEach(function (a) { attrOwner[a.uuid] = obj.uuid; });
        });
        (ev.Object || []).forEach(function (obj) {
            (obj.ObjectReference || []).forEach(function (ref) {
                if (isDeleted(ref)) return;
                connectedObjUuids[obj.uuid] = true;
                if (String(ref.referenced_type) === '1') {
                    connectedObjUuids[ref.referenced_uuid] = true;
                } else {
                    referencedAttrUuids[ref.referenced_uuid] = true;
                    if (attrOwner[ref.referenced_uuid]) {
                        connectedObjUuids[attrOwner[ref.referenced_uuid]] = true;
                    }
                }
            });
        });
        return { referencedAttrUuids: referencedAttrUuids, connectedObjUuids: connectedObjUuids };
    }

    // Shared object node data (graph builder + editor drop handler).
    function objectNodeData(obj) {
        return compact({
            type:            'object',
            label:           truncate(obj.name || 'Object', 42),
            description:     obj['meta-category'] ? (obj['meta-category'] + ' object') : 'Object',
            name:            obj.name,
            'meta-category': obj['meta-category'],
            uuid:            obj.uuid
        });
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

        /* Which event-level attributes are pointed at by an object reference?
           (referenced_type 0 = attribute). These are the only standalone
           attributes worth showing — they anchor to the object graph rather
           than floating free, and this also covers referenced screenshots. */
        var conn                = computeConnectivity(ev);
        var referencedAttrUuids = conn.referencedAttrUuids;
        var connectedObjUuids   = conn.connectedObjUuids;

        /* Event-level attributes: surfaced only when an object references them,
           so every node stays connected to the graph. */
        (ev.Attribute || []).forEach(function (attr) {
            if (!isDeleted(attr) && referencedAttrUuids[attr.uuid]) {
                addAttributeNode(attr);
            }
        });

        /* Objects and their attributes (attributes nested inside the object) */
        (ev.Object || []).forEach(function (obj) {
            if (isDeleted(obj)) return;
            // Reference-less objects live in the editor tray, not the canvas.
            if (!connectedObjUuids[obj.uuid]) return;
            var objId = 'obj:' + obj.uuid;

            // Attributes are nested as children of their object rather than
            // linked by an edge — containment expresses the object/attribute
            // relationship (the object_relation is folded into the description).
            var children = [];
            (obj.Attribute || []).forEach(function (attr) {
                if (isDeleted(attr)) return;
                var child = buildAttributeNode(attr);
                if (child) children.push(child);
            });

            addNode(objId, {
                id:       objId,
                children: children,
                data:     objectNodeData(obj)
            });
        });

        /* Object references (added last so both ends already exist) */
        (ev.Object || []).forEach(function (obj) {
            var objId = 'obj:' + obj.uuid;
            (obj.ObjectReference || []).forEach(function (ref) {
                if (isDeleted(ref)) return;
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
                    textVerticalShift: -1,
                    // Newly dragged-in, not-yet-referenced nodes wear an orange ring
                    // until their relationship is saved.
                    styleCb: function (node) {
                        var d = node.getData();
                        if (d && d.pending) {
                            return { strokeColor: '#f39a1f', strokeWidth: 3 };
                        }
                        return {};
                    }
                },
                // Draw the relationship_type on every edge (referenced + newly created).
                defaultLabelStyle: {
                    labelAccessor: function (edge) {
                        var d = edge.getData ? edge.getData() : null;
                        return d ? (d.label || '') : '';
                    }
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
                _event   = event;
                var data = buildGraphData(event);

                if (loaderEl)    loaderEl.style.display    = 'none';
                if (containerEl) containerEl.style.display = '';

                // Build the editor first so its sidebar panel can be handed to
                // pivotick at construction time (extraPanels are options-time only).
                var editor = canEdit ? createEditor(event) : null;
                var opts   = graphOptions();
                if (editor) opts.UI.extraPanels = [editor.panel];

                _graph = new window.Pivotick(containerEl, data, opts);

                if (editor) {
                    try { editor.attach(_graph); }
                    catch (e) { console.error('[pivot-explorer] editor attach failed:', e); }
                }
            })
            .catch(function (err) {
                console.error('[pivot-explorer] graph build failed:', err);
                _initialized = false;   // allow a retry on the next tab activation
                if (loaderEl) loaderEl.innerHTML =
                    '<p class="text-danger mb-0"><i class="fas fa-exclamation-triangle me-2"></i>'
                    + <?= json_encode(h(__('Failed to load event graph.'))) ?> + '</p>';
            });
    }

    /* ══════════════════════════════════════════════════════════
       EDITOR
       - a pivotick sidebar extraPanel listing the event's unlinked
         attributes as draggable chips
       - drop a chip on the canvas to stage its node
       - draw an edge with pivotick's Edit ▸ Add edge tool; we intercept
         edgeAdd to validate the source, pick a relationship, and persist
       ══════════════════════════════════════════════════════════ */
    function createEditor(event) {
        var ev = (event && event.Event) ? event.Event : {};

        var graph      = null;
        var stageEl    = document.getElementById('pe-stage');

        // DOM refs into the panel body (built once, on first render()).
        var panelEl    = null;
        var listEl     = null;
        var badgeEl    = null;
        var filterEl   = null;
        var filterVal  = '';

        var staged = {};   // attr uuid -> { nodeId, saved }

        /* ── unlinked inventory (what's NOT on the canvas) ──── */
        // Same connectivity rule as the canvas builder, so the tray lists exactly
        // the attributes/objects buildGraphData chose to omit.
        var conn           = computeConnectivity(ev);
        var referencedAttr = conn.referencedAttrUuids;
        var connectedObj   = conn.connectedObjUuids;
        var items = [];
        (ev.Attribute || []).forEach(function (a) {
            if (isDeleted(a) || referencedAttr[a.uuid]) return;
            items.push({
                kind:  'attribute', uuid: a.uuid, attr: a,
                label: (a.value != null ? String(a.value) : ''),
                meta:  (a.type || '') + (a.to_ids ? ' · IDS' : ''),
                group: a.category || 'Other'
            });
        });
        (ev.Object || []).forEach(function (o) {
            if (isDeleted(o) || connectedObj[o.uuid]) return;
            items.push({
                kind:  'object', uuid: o.uuid, obj: o,
                label: (o.name || 'Object'),
                meta:  (o['meta-category'] || 'object'),
                group: 'Objects'
            });
        });
        var itemsByUuid = {};
        items.forEach(function (it) { itemsByUuid[it.uuid] = it; });

        /* ── drag ghost (follows the cursor during a drag) ──── */
        var EMPTY_IMG = new Image();
        EMPTY_IMG.src = 'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7';
        var ghostEl = null;
        function moveGhost(e) {
            if (ghostEl) { ghostEl.style.left = (e.clientX + 14) + 'px'; ghostEl.style.top = (e.clientY + 14) + 'px'; }
        }
        function startGhost(item) {
            endGhost();
            ghostEl = document.createElement('div');
            ghostEl.className = 'pe-ghost pe-ghost-' + item.kind;
            ghostEl.textContent = truncate(item.label, 32);
            document.body.appendChild(ghostEl);
            document.addEventListener('dragover', moveGhost);
        }
        function endGhost() {
            if (ghostEl) { if (ghostEl.parentNode) ghostEl.parentNode.removeChild(ghostEl); ghostEl = null; }
            document.removeEventListener('dragover', moveGhost);
        }

        /* ── notifications (fall back to console) ──────────── */
        function notify(kind, title, msg) {
            var n = graph && graph.notifier;
            if (n && typeof n[kind] === 'function') { n[kind](title, msg); return; }
            console.log('[pivot-explorer] ' + kind + ': ' + title + (msg ? ' — ' + msg : ''));
        }

        /* ── panel (extraPanel render) ─────────────────────── */
        function buildPanel() {
            panelEl = document.createElement('div');
            panelEl.className = 'pe-tray-body';

            var count = document.createElement('div');
            count.className = 'pe-count';
            count.textContent = 'Unlinked ';
            badgeEl = document.createElement('span');
            badgeEl.className = 'pe-badge';
            count.appendChild(badgeEl);

            filterEl = document.createElement('input');
            filterEl.type = 'text';
            filterEl.className = 'pe-filter';
            filterEl.placeholder = 'Filter…';
            filterEl.autocomplete = 'off';
            filterEl.value = filterVal;
            filterEl.addEventListener('input', function () {
                filterVal = filterEl.value;
                renderList();
            });

            listEl = document.createElement('div');
            listEl.className = 'pe-tray-list';

            panelEl.appendChild(count);
            panelEl.appendChild(filterEl);
            panelEl.appendChild(listEl);

            renderList();
            updateCount();
            return panelEl;
        }

        function renderList() {
            if (!listEl) return;
            var filter = (filterVal || '').toLowerCase();
            listEl.innerHTML = '';
            var groups = {};
            items.forEach(function (it) {
                var hay = (it.label + ' ' + it.meta + ' ' + it.group).toLowerCase();
                if (filter && hay.indexOf(filter) === -1) return;
                (groups[it.group] = groups[it.group] || []).push(it);
            });
            var keys = Object.keys(groups).sort();
            if (!keys.length) {
                listEl.innerHTML = '<div class="pe-empty">'
                    + (items.length ? 'No matches.' : 'Nothing unlinked.') + '</div>';
                return;
            }
            keys.forEach(function (g) {
                var lbl = document.createElement('div');
                lbl.className = 'pe-group-label';
                lbl.textContent = g;
                listEl.appendChild(lbl);
                groups[g].forEach(function (it) { listEl.appendChild(buildChip(it)); });
            });
        }

        function buildChip(item) {
            var isStaged = !!staged[item.uuid];
            var chip = document.createElement('div');
            chip.className = 'pe-chip pe-chip-' + item.kind + (isStaged ? ' pe-chip-staged' : '');
            chip.setAttribute('draggable', isStaged ? 'false' : 'true');
            var v = document.createElement('div');
            v.className = 'pe-chip-val';
            v.textContent = truncate(item.label, 48);
            var m = document.createElement('div');
            m.className = 'pe-chip-meta';
            m.textContent = item.meta;
            chip.appendChild(v); chip.appendChild(m);
            chip.addEventListener('dragstart', function (e) {
                e.dataTransfer.setData('text/plain', item.uuid);
                e.dataTransfer.effectAllowed = 'copy';
                try { e.dataTransfer.setDragImage(EMPTY_IMG, 0, 0); } catch (_) {}
                startGhost(item);
            });
            chip.addEventListener('dragend', endGhost);
            return chip;
        }

        function updateCount() {
            if (!badgeEl) return;
            badgeEl.textContent = items.filter(function (it) { return !staged[it.uuid]; }).length;
        }

        /* ── drop a chip onto the canvas → staged node ─────── */
        // screenToGraphCoordinates() expects raw viewport coordinates — it
        // subtracts the canvas rect and inverts the zoom transform itself.
        function graphCoords(clientX, clientY) {
            var r = graph && graph.renderer;
            if (r && typeof r.screenToGraphCoordinates === 'function') {
                try { return r.screenToGraphCoordinates(clientX, clientY); }
                catch (e) { /* fall through */ }
            }
            return null;
        }

        function stageItem(uuid, clientX, clientY) {
            var it = itemsByUuid[uuid];
            if (!it || staged[uuid]) return;
            var raw, nodeId;
            if (it.kind === 'object') {
                nodeId = 'obj:' + uuid;
                var children = (it.obj.Attribute || []).filter(function (a) { return !isDeleted(a); })
                    .map(function (a) { return { id: 'attr:' + a.uuid, data: attributeNodeData(a) }; });
                var odata = objectNodeData(it.obj);
                odata.pending = true;
                raw = { id: nodeId, children: children, data: odata };
            } else {
                nodeId = 'attr:' + uuid;
                var adata = attributeNodeData(it.attr);
                adata.pending = true;
                raw = { id: nodeId, data: adata };
            }
            var c = graphCoords(clientX, clientY);
            if (c) { raw.fx = c.x; raw.fy = c.y; }   // pin where dropped
            try {
                graph.addNode(raw);
            } catch (e) {
                console.error('[pivot-explorer] addNode failed:', e);
                return;
            }
            staged[uuid] = { nodeId: nodeId, saved: false };
            if (graph.simulation && typeof graph.simulation.reheat === 'function') {
                graph.simulation.reheat();
            }
            renderList();
            updateCount();
        }

        function wireDrop() {
            if (!stageEl) return;
            stageEl.addEventListener('dragover', function (e) {
                e.preventDefault();
                e.dataTransfer.dropEffect = 'copy';
                stageEl.classList.add('pe-drop-active');
            });
            stageEl.addEventListener('dragleave', function (e) {
                if (e.target === stageEl) stageEl.classList.remove('pe-drop-active');
            });
            stageEl.addEventListener('drop', function (e) {
                e.preventDefault();
                stageEl.classList.remove('pe-drop-active');
                var uuid = e.dataTransfer.getData('text/plain');
                if (uuid) stageItem(uuid, e.clientX, e.clientY);
                endGhost();
            });
        }

        /* ── edge creation → validate, pick relationship, save ─ */
        function resolveNode(ref) {
            if (ref && typeof ref.getData === 'function') return ref;
            if (typeof graph.getNode === 'function') return graph.getNode(ref);
            return null;
        }
        function edgeId(edge) {
            return typeof edge.getId === 'function' ? edge.getId() : edge.id;
        }

        function onEdgeAdd(edge) {
            // Only user-drawn edges reach here — the listener is attached after
            // the graph (with its referenced edges) is already built.
            var fromNode = resolveNode(edge.from !== undefined ? edge.from : edge.source);
            var toNode   = resolveNode(edge.to   !== undefined ? edge.to   : edge.target);
            var fromData = fromNode && fromNode.getData ? fromNode.getData() : null;
            var toData   = toNode   && toNode.getData   ? toNode.getData()   : null;
            var eid      = edgeId(edge);

            if (!fromData || !toData) return;

            // MISP references are owned by an object → the source must be an object.
            if (fromData.type !== 'object') {
                notify('error', 'Invalid source', 'A relationship must start from an object node.');
                if (typeof graph.removeEdge === 'function') graph.removeEdge(eid);
                return;
            }

            var sourceUuid = fromData.uuid;
            var targetUuid = toData.uuid;

            showRelationshipPicker(function (rel) {
                saveReference(sourceUuid, targetUuid, rel, edge, eid);
            }, function () {   // cancelled
                if (typeof graph.removeEdge === 'function') graph.removeEdge(eid);
            });
        }

        // Mark a staged node saved and drop its pending ring, whichever end it is.
        function clearPending(uuid) {
            if (staged[uuid]) staged[uuid].saved = true;
            var live = typeof graph.getMutableNode === 'function'
                ? (graph.getMutableNode('obj:' + uuid) || graph.getMutableNode('attr:' + uuid))
                : null;
            if (live && live.updateData) live.updateData({ pending: undefined });
        }

        function saveReference(sourceUuid, targetUuid, rel, edge, eid) {
            fetch(baseurl + '/objectReferences/add/' + encodeURIComponent(sourceUuid) + '.json', {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Content-Type':     'application/json',
                    'Accept':           'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify({
                    ObjectReference: {
                        referenced_uuid:   targetUuid,
                        relationship_type: rel,
                        comment:           ''
                    }
                })
            })
            .then(function (res) {
                if (!res.ok) {
                    return res.json().catch(function () { return {}; })
                        .then(function (body) {
                            throw new Error((body && (body.errors || body.message)) || ('HTTP ' + res.status));
                        });
                }
                return res.json().catch(function () { return {}; });
            })
            .then(function () {
                if (edge.updateData) edge.updateData({ label: rel });
                else if (edge.setData) edge.setData({ label: rel });
                clearPending(sourceUuid);   // a staged object can be the source
                clearPending(targetUuid);
                if (graph.simulation && graph.simulation.reheat) graph.simulation.reheat();
                notify('success', 'Relationship added', rel);
            })
            .catch(function (err) {
                console.error('[pivot-explorer] save failed:', err);
                if (typeof graph.removeEdge === 'function') graph.removeEdge(eid);
                notify('error', 'Save failed', String(err && err.message || err));
            });
        }

        /* ── relationship picker ───────────────────────────── */
        function showRelationshipPicker(onConfirm, onCancel) {
            var backdrop = document.createElement('div');
            backdrop.className = 'pe-picker-backdrop';
            var opts = DEFAULT_RELATIONSHIPS.map(function (r) {
                return '<option value="' + r + '">' + r + '</option>';
            }).join('');
            backdrop.innerHTML =
                '<div class="pe-picker">' +
                    '<h4>Add relationship</h4>' +
                    '<div class="pe-picker-sub">object → target</div>' +
                    '<label>Relationship type</label>' +
                    '<select class="pe-picker-select">' + opts +
                        '<option value="__custom">custom…</option></select>' +
                    '<input type="text" class="pe-picker-custom" placeholder="custom relationship" ' +
                        'style="display:none;margin-top:.4rem;">' +
                    '<div class="pe-picker-actions">' +
                        '<button type="button" class="pe-picker-btn pe-picker-cancel">Cancel</button>' +
                        '<button type="button" class="pe-picker-btn pe-btn-primary pe-picker-save">Save</button>' +
                    '</div>' +
                '</div>';
            (stageEl || document.body).appendChild(backdrop);

            var sel    = backdrop.querySelector('.pe-picker-select');
            var custom = backdrop.querySelector('.pe-picker-custom');
            sel.value = 'related-to';
            sel.addEventListener('change', function () {
                custom.style.display = sel.value === '__custom' ? '' : 'none';
                if (sel.value === '__custom') custom.focus();
            });
            function close() { if (backdrop.parentNode) backdrop.parentNode.removeChild(backdrop); }
            backdrop.querySelector('.pe-picker-cancel').addEventListener('click', function () {
                close(); onCancel();
            });
            backdrop.querySelector('.pe-picker-save').addEventListener('click', function () {
                var rel = sel.value === '__custom' ? custom.value.trim() : sel.value;
                if (!rel) { custom.focus(); return; }
                close(); onConfirm(rel);
            });
        }

        /* ── public: panel def (options-time) + attach (post-construction) ── */
        return {
            panel: {
                title: 'Unlinked attributes',
                alwaysVisible: true,
                render: function () { return panelEl || buildPanel(); }
            },
            attach: function (g) {
                graph = g;
                wireDrop();
                if (typeof graph.on === 'function') graph.on('edgeAdd', onEdgeAdd);
                updateCount();
            }
        };
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
