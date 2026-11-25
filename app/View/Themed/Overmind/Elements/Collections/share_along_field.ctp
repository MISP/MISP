<?php
/*
 * Share these too, on the collection's edit form: when the sharing picked
 * reaches further than the collection's, what its organisation drew on it
 * and reaches fewer (saved graphs, links between members), ticked to take
 * the new sharing when the form saves. Posted as Collection.share_along,
 * JSON {graphs: [uuid], relationships: [uuid]}.
 *
 * Params:
 *   $collectionId  int     the collection
 *   $stored        array   its sharing as stored: distribution, sharing_group_id
 *   $accent        string  the form's accent key
 */
$this->Form->unlockField('Collection.share_along');

$text = [
    'nodes' => [__('%s node'), __('%s nodes')],
    'ticked' => __('%s of %s ticked'),
    'wasNarrower' => __('kept narrower than the collection'),
    'loading' => __('Looking at what is drawn on the collection…'),
    'failed' => __('What is drawn on the collection could not be listed: it keeps its sharing.'),
    'related' => __('related'),
    'notVisible' => __('Not visible to you'),
    'tickAll' => __('Tick or untick all %s'),
];
$sections = [
    'graphs' => [__('Saved graphs'), 'misp-icon misp-icon-analyst-graph misp-simple'],
    'relationships' => [__('Links between members'), 'fas fa-link'],
];
$types = [
    'Event' => ['misp-icon misp-icon-event misp-simple', 'event'],
    'Attribute' => ['misp-icon misp-icon-attribute misp-simple', 'attribute'],
    'Object' => ['misp-icon misp-icon-object misp-simple', 'object'],
    'GalaxyCluster' => ['misp-icon misp-icon-galaxy misp-simple', 'galaxy'],
    'AttributeValue' => ['misp-icon misp-icon-value-intelligence misp-simple', 'valueIntelligence'],
    'Value' => ['misp-icon misp-icon-value-intelligence misp-simple', 'valueIntelligence'],
    'StandaloneObject' => ['misp-icon misp-icon-object misp-simple', 'object'],
    'Collection' => ['fas fa-folder', 'primary'],
];
$json = JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE;
?>
<style>
.csa[hidden] { display: none; }
.csa-lead { margin: 0 0 .6rem; color: var(--bs-secondary-color); font-size: .78rem; line-height: 1.4; }
.csa-box { border: 1px solid var(--bs-border-color); border-radius: .5rem; overflow: hidden; }
.csa-sec + .csa-sec { border-top: 1px solid var(--bs-border-color); }
.csa-head { display: flex; align-items: center; gap: .6rem; padding: .5rem .85rem; font-size: .85rem; background: var(--bs-tertiary-bg); }
.csa-head .form-check-input { flex: none; margin: 0; }
.csa-count { margin-left: auto; padding: .1rem .5rem; border-radius: 999px; background: var(--bs-secondary-bg); color: var(--bs-secondary-color); font-size: .72rem; font-weight: 600; white-space: nowrap; }
.csa-list { list-style: none; margin: 0; padding: 0; max-height: 15rem; overflow-y: auto; border-top: 1px solid var(--bs-border-color-translucent); }
.csa-row { display: flex; align-items: center; gap: .65rem; padding: .45rem .85rem; min-width: 0; cursor: pointer; }
.csa-row + .csa-row { border-top: 1px solid var(--bs-border-color-translucent); }
.csa-row:hover { background: var(--bs-tertiary-bg); }
.csa-row .form-check-input { flex: none; margin: 0; }
.csa-row:not(.is-on) .csa-body { opacity: .7; }
.csa-tile { flex: none; display: inline-flex; align-items: center; justify-content: center; width: 1.75rem; height: 1.75rem; border-radius: .45rem; font-size: .8rem; background: rgba(var(--bs-analystGraph-rgb, 13, 110, 253), .12); color: rgb(var(--bs-analystGraph-rgb, 13, 110, 253)); }
.csa-body { flex: 1 1 auto; min-width: 0; line-height: 1.25; font-size: .82rem; }
.csa-name { font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.csa-meta { display: flex; align-items: center; flex-wrap: wrap; gap: .25rem .45rem; margin-top: .15rem; color: var(--bs-secondary-color); font-size: .72rem; }
.csa-level { display: inline-flex; align-items: center; gap: .3rem; padding: .05rem .45rem; border-radius: 999px; border: 1px solid; font-size: .68rem; font-weight: 500; white-space: nowrap; }
.csa-kept { color: var(--bs-secondary-color); font-style: italic; }
.csa-link { display: flex; align-items: center; gap: .45rem; min-width: 0; }
.csa-end { display: inline-flex; align-items: center; gap: .35rem; min-width: 0; flex: 0 1 auto; }
.csa-end > i { flex: none; font-size: .78rem; }
.csa-end > span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-weight: 600; }
.csa-end > span.is-hidden { font-weight: 400; font-style: italic; color: var(--bs-secondary-color); }
.csa-rel { flex: none; padding: .05rem .5rem; border-radius: 999px; background: rgba(var(--bs-analystData-rgb, 111, 66, 193), .1); color: rgb(var(--bs-analystData-rgb, 111, 66, 193)); font-size: .68rem; font-weight: 600; white-space: nowrap; }
.csa-quiet { padding: .75rem .85rem; border: 1px dashed var(--bs-border-color); border-radius: .5rem; color: var(--bs-secondary-color); font-size: .78rem; }
@media (max-width: 575.98px) { .csa-link { flex-wrap: wrap; } }
</style>

<div class="csa w-100" id="collection-share-along" hidden
     data-collection-id="<?= h((int)$collectionId) ?>"
     data-distribution="<?= h((string)(int)($stored['distribution'] ?? 0)) ?>"
     data-sharing-group="<?= h((int)($stored['distribution'] ?? 0) === 4 ? (string)(int)$stored['sharing_group_id'] : '') ?>">
    <?= $this->element('genericElementsBS5/Forms/section_label', [
        'accent' => $accent ?? 'primary',
        'label' => __('Share these too'),
    ]) ?>
    <p class="csa-lead"><?= h(__('What is drawn on the collection keeps its own sharing. Ticked ones take the collection’s new sharing when you save.')) ?></p>
    <div data-share-along-body></div>
    <input type="hidden" name="data[Collection][share_along]" value="" data-share-along-input>
</div>

<script>
(function () {
    var root = document.getElementById('collection-share-along');
    if (!root || root.dataset.bound) return;
    root.dataset.bound = '1';
    var form = root.closest('form');
    var dist = form && form.querySelector('#distribution-select');
    if (!dist) return;
    var T = <?= json_encode($text, $json) ?>;
    var SECTIONS = <?= json_encode($sections, $json) ?>;
    var TYPES = <?= json_encode($types, $json) ?>;
    var LEVELS = <?= json_encode($this->DistributionLevel->all(), $json) ?>;
    var BASE = <?= json_encode($baseurl, $json) ?>;
    var body = root.querySelector('[data-share-along-body]');
    var input = root.querySelector('[data-share-along-input]');
    var stored = { distribution: root.dataset.distribution, sharing_group_id: root.dataset.sharingGroup || '' };
    var plan = null;
    var touched = {};
    var seq = 0;

    function fill(s, args) {
        var i = 0;
        return String(s).replace(/%s/g, function () { return String(args[i++]); });
    }
    function n(pair, count) { return fill(pair[count === 1 ? 0 : 1], [count]); }
    function el(tag, cls, text) {
        var e = document.createElement(tag);
        if (cls) e.className = cls;
        if (text != null) e.textContent = text;
        return e;
    }
    function icon(cls) {
        var i = el('i', cls);
        i.setAttribute('aria-hidden', 'true');
        return i;
    }
    function sgSelect() { return form.querySelector('#sharing-group-select'); }
    function chosen() {
        var sg = sgSelect();
        return { distribution: String(dist.value), sharing_group_id: dist.value === '4' && sg ? String(sg.value || '') : '' };
    }
    function same(a, b) {
        return a.distribution === b.distribution && (a.distribution !== '4' || a.sharing_group_id === b.sharing_group_id);
    }
    function on(kind, item) {
        var key = kind + ':' + item.uuid;
        return Object.prototype.hasOwnProperty.call(touched, key) ? touched[key] : !!item.ticked;
    }
    function items(kind) { return plan && plan[kind] ? plan[kind].items || [] : []; }

    function sync() {
        if (!plan || root.hidden) {
            input.value = '';
            return;
        }
        var picked = { graphs: [], relationships: [] };
        Object.keys(picked).forEach(function (kind) {
            items(kind).forEach(function (item) { if (on(kind, item)) picked[kind].push(item.uuid); });
        });
        input.value = JSON.stringify(picked);
        root.querySelectorAll('[data-csa-section]').forEach(function (sec) {
            var kind = sec.getAttribute('data-csa-section');
            var list = items(kind);
            var count = list.filter(function (item) { return on(kind, item); }).length;
            var all = sec.querySelector('[data-csa-all]');
            all.checked = count === list.length;
            all.indeterminate = count > 0 && count < list.length;
            sec.querySelector('.csa-count').textContent = fill(T.ticked, [count, list.length]);
            sec.querySelectorAll('[data-csa-uuid]').forEach(function (row) {
                var isOn = on(kind, { uuid: row.getAttribute('data-csa-uuid'), ticked: row.getAttribute('data-csa-default') === '1' });
                row.classList.toggle('is-on', isOn);
                row.querySelector('input').checked = isOn;
            });
        });
    }

    function levelPill(item) {
        var meta = LEVELS[item.distribution] || {};
        var tone = function (role, value) {
            return meta.token ? 'var(--misp-' + meta.token + '-' + role + ', ' + value + ')' : value;
        };
        var pill = el('span', 'csa-level');
        pill.style.backgroundColor = tone('bg', meta.bg || 'transparent');
        pill.style.color = tone('fg', meta.color || 'inherit');
        pill.style.borderColor = tone('border', (meta.color || '#6c757d') + '33');
        if (meta.icon) pill.appendChild(icon(meta.icon));
        pill.appendChild(el('span', null, item.sharing_group && item.sharing_group.name ? item.sharing_group.name : (meta.label || String(item.distribution))));
        return pill;
    }
    function end(e) {
        var type = TYPES[e.type] || ['fas fa-cube', 'secondary'];
        var wrap = el('span', 'csa-end');
        var glyph = icon(type[0]);
        glyph.style.color = 'rgb(var(--bs-' + type[1] + '-rgb))';
        wrap.appendChild(glyph);
        var hasLabel = e.label !== null && e.label !== undefined && e.label !== '';
        var name = el('span', hasLabel ? null : 'is-hidden', hasLabel ? e.label : T.notVisible);
        if (!hasLabel) name.title = e.address || '';
        wrap.appendChild(name);
        return wrap;
    }
    function row(kind, item, index) {
        var li = el('li');
        var label = el('label', 'csa-row');
        label.setAttribute('data-csa-uuid', item.uuid);
        label.setAttribute('data-csa-default', item.ticked ? '1' : '0');
        var box = el('input', 'form-check-input');
        box.type = 'checkbox';
        box.id = 'csa-' + kind + '-' + index;
        box.addEventListener('change', function () {
            touched[kind + ':' + item.uuid] = box.checked;
            sync();
        });
        label.appendChild(box);
        var bodyEl = el('div', 'csa-body');
        var meta = el('div', 'csa-meta');
        if (kind === 'graphs') {
            var tile = el('span', 'csa-tile');
            tile.appendChild(icon(SECTIONS.graphs[1]));
            label.appendChild(tile);
            bodyEl.appendChild(el('div', 'csa-name', item.name));
            meta.appendChild(el('span', null, n(T.nodes, item.node_count || 0)));
        } else {
            var link = el('div', 'csa-link');
            link.appendChild(end(item.from));
            var rel = el('span', 'csa-rel', item.relationship_type || T.related);
            rel.appendChild(icon('fas fa-arrow-right-long ms-1'));
            link.appendChild(rel);
            link.appendChild(end(item.to));
            bodyEl.appendChild(link);
        }
        meta.appendChild(levelPill(item));
        if (!item.ticked) meta.appendChild(el('span', 'csa-kept', T.wasNarrower));
        bodyEl.appendChild(meta);
        label.appendChild(bodyEl);
        li.appendChild(label);
        return li;
    }
    function section(kind) {
        var list = items(kind);
        var sec = el('div', 'csa-sec');
        sec.setAttribute('data-csa-section', kind);
        var head = el('label', 'csa-head');
        var all = el('input', 'form-check-input');
        all.type = 'checkbox';
        all.setAttribute('data-csa-all', '');
        all.setAttribute('aria-label', fill(T.tickAll, [SECTIONS[kind][0].toLowerCase()]));
        all.addEventListener('change', function () {
            list.forEach(function (item) { touched[kind + ':' + item.uuid] = all.checked; });
            sync();
        });
        head.appendChild(all);
        head.appendChild(icon(SECTIONS[kind][1]));
        head.appendChild(el('span', 'fw-semibold', SECTIONS[kind][0]));
        head.appendChild(el('span', 'csa-count'));
        sec.appendChild(head);
        var ul = el('ul', 'csa-list');
        list.forEach(function (item, i) { ul.appendChild(row(kind, item, i)); });
        sec.appendChild(ul);
        return sec;
    }
    function render() {
        body.textContent = '';
        var kinds = ['graphs', 'relationships'].filter(function (kind) { return items(kind).length > 0; });
        root.hidden = kinds.length === 0;
        if (!kinds.length) {
            sync();
            return;
        }
        var box = el('div', 'csa-box');
        kinds.forEach(function (kind) { box.appendChild(section(kind)); });
        body.appendChild(box);
        sync();
    }
    function quiet(text, spin) {
        plan = null;
        root.hidden = false;
        body.textContent = '';
        var q = el('div', 'csa-quiet');
        q.appendChild(icon(spin ? 'fas fa-circle-notch fa-spin me-2' : 'fas fa-circle-info me-2'));
        q.appendChild(document.createTextNode(text));
        body.appendChild(q);
        sync();
    }

    function refresh() {
        var c = chosen();
        var mine = ++seq;
        if (same(c, stored) || (c.distribution === '4' && !c.sharing_group_id)) {
            plan = null;
            root.hidden = true;
            body.textContent = '';
            sync();
            return;
        }
        quiet(T.loading, true);
        var url = BASE + '/collections/shareAlong/' + encodeURIComponent(root.dataset.collectionId) + '.json?distribution=' + encodeURIComponent(c.distribution)
            + (c.distribution === '4' ? '&sharing_group_id=' + encodeURIComponent(c.sharing_group_id) : '');
        fetch(url, { credentials: 'same-origin', headers: { Accept: 'application/json', 'X-Requested-With': 'XMLHttpRequest' } })
            .then(function (r) { return r.ok ? r.json() : Promise.reject(new Error(String(r.status))); })
            .then(function (answer) {
                if (mine !== seq) return;
                plan = answer;
                render();
            }, function () {
                if (mine !== seq) return;
                quiet(T.failed, false);
            });
    }

    form.addEventListener('change', function (e) {
        if (e.target === dist || e.target === sgSelect()) refresh();
    });
    refresh();
}());
</script>
