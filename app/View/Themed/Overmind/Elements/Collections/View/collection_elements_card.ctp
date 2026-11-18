<?php
App::uses('ValueUrlTool', 'Tools/ValueIntelligence');
$collection = $data['Collection'] ?? $data;
$elements = $collection['CollectionElement'] ?? [];
$canEdit = !empty($isSiteAdmin) || !empty($mayModify);
$adders = $elementAdders ?? [];
$pageSize = 50;

// element_type => [glyph, scope colour (a --bs-<scope>-rgb triplet), label]
$scopes = [
    'Event'         => ['misp-icon misp-icon-event misp-simple', 'event', __('Event')],
    'Attribute'     => ['misp-icon misp-icon-attribute misp-simple', 'attribute', __('Attribute')],
    'Object'        => ['misp-icon misp-icon-object misp-simple', 'object', __('Object')],
    'AttributeValue' => ['misp-icon misp-icon-value-intelligence misp-simple', 'valueIntelligence', __('Value')],
    'Galaxy'        => ['misp-icon misp-icon-galaxy misp-simple', 'galaxy', __('Galaxy')],
    'GalaxyCluster' => ['misp-icon misp-icon-galaxy misp-simple', 'galaxy', __('Galaxy cluster')],
    'Note'          => ['misp-icon misp-icon-analyst-note misp-simple', 'analystData', __('Note')],
    'Opinion'       => ['misp-icon misp-icon-analyst-opinion misp-simple', 'analystData', __('Opinion')],
    'Relationship'  => ['fas fa-link', 'analystData', __('Relationship')],
    'Organisation'  => ['misp-icon misp-icon-organisation misp-simple', 'primary', __('Organisation')],
    'SharingGroup'  => ['misp-icon misp-icon-sharing-group misp-simple', 'primary', __('Sharing group')],
];
$fallbackScope = ['fas fa-cube', 'secondary', null];

// An object named by its most telling value, as the working view names it
$objectTitle = function ($name, array $attributes) {
    $values = [];
    foreach ($attributes as $attribute) {
        $relation = $attribute['object_relation'] ?? $attribute['relation'] ?? null;
        if ($relation !== null && !isset($values[$relation])) {
            $values[$relation] = (string)$attribute['value'];
        }
    }
    foreach (['domain', 'hostname', 'url', 'ip', 'ip-dst', 'ip-src'] as $relation) {
        if (isset($values[$relation])) {
            return $name . ': ' . $values[$relation];
        }
    }
    return empty($values) ? (string)$name : $name . ': ' . reset($values);
};
$originText = function ($origin) {
    if (!is_array($origin) || empty($origin['module'])) {
        return null;
    }
    $text = !empty($origin['value'])
        ? __('from %s on %s', $origin['module'], $origin['value'])
        : __('from %s', $origin['module']);
    return empty($origin['ran_at']) ? $text : $text . __(', %s', gmdate('Y-m-d', (int)$origin['ran_at']));
};

$rows = [];
$typeCounts = [];
foreach ($elements as $element) {
    $type = (string)($element['element_type'] ?? '');
    $uuid = (string)($element['element_uuid'] ?? '');
    // A standalone object is counted and filtered with the objects
    $kind = $type === 'StandaloneObject' ? 'Object' : $type;
    $title = null;
    $refId = null;
    $subtitle = null;
    $url = null;
    $missing = false;
    $record = null;
    $key = $type . ':' . strtolower($uuid);
    if ($type === 'Attribute' && !empty($element['Attribute'])) {
        $attribute = $element['Attribute'];
        $title = (string)$attribute['value'];
        $refId = (int)$attribute['event_id'];
        $subtitle = $attribute['type'] ?? null;
        $url = $baseurl . '/attributes/view/' . $attribute['id'];
    } elseif ($type === 'Object' && !empty($element['Object'])) {
        $object = $element['Object'];
        $title = $objectTitle($object['name'], $object['Attribute'] ?? []);
        $refId = (int)$object['event_id'];
        $subtitle = $object['meta-category'] ?? null;
        $url = $baseurl . '/objects/view/' . $object['id'];
    } elseif ($type === 'AttributeValue') {
        $sha256 = strtolower((string)($element['element_sha256'] ?? ''));
        $key = 'Value:' . $sha256;
        $uuid = $sha256;
        if (!empty($element['AttributeValue'])) {
            $uuid = '';
            $title = (string)$element['AttributeValue']['value'];
            $missing = empty($element['AttributeValue']['held']);
            $url = $missing ? null : $baseurl . '/values/view/' . ValueUrlTool::address($title);
        }
    } elseif ($type === 'StandaloneObject' && !empty($element['StandaloneObject'])) {
        $record = $element['StandaloneObject'];
        $title = $objectTitle($record['name'], $record['attributes'] ?? []);
        $missing = true;
    } elseif ($type === 'Event' && !empty($element['Event'])) {
        $title = $element['Event']['info'];
        $refId = (int)$element['Event']['id'];
        $url = $baseurl . '/events/view/' . $element['Event']['id'];
    } elseif ($type === 'GalaxyCluster' && !empty($element['GalaxyCluster'][0])) {
        $cluster = $element['GalaxyCluster'][0];
        $title = $cluster['value'] ?? null;
        $refId = (int)$cluster['id'];
        $subtitle = $cluster['Galaxy']['name'] ?? ($cluster['type'] ?? null);
        $url = $baseurl . '/galaxy_clusters/view/' . $cluster['id'];
    } elseif ($uuid !== '') {
        $byUuid = [
            'Galaxy' => '/galaxies/view/',
            'Organisation' => '/organisations/view/',
            'SharingGroup' => '/sharing_groups/view/',
            'Note' => '/analystData/view/all/',
            'Opinion' => '/analystData/view/all/',
            'Relationship' => '/analystData/view/all/',
        ];
        if (isset($byUuid[$type])) {
            $url = $baseurl . $byUuid[$type] . $uuid;
        }
    }

    $typeCounts[$kind] = ($typeCounts[$kind] ?? 0) + 1;
    $origin = is_array($element['origin'] ?? null) ? $element['origin'] : null;
    $rows[] = [
        'id' => (int)$element['id'],
        'type' => $kind,
        'key' => $key,
        'uuid' => $uuid,
        'title' => $title,
        'rid' => $refId,
        'sub' => $subtitle,
        'url' => $url,
        'desc' => trim((string)($element['description'] ?? '')),
        'missing' => $missing,
        'origin' => $origin,
        'from' => $originText($origin),
        'record' => $record,
        'who' => isset($element['user_id']) ? ($adders[$element['user_id']] ?? null) : null,
        'when' => $element['created'] ?? null,
    ];
}
arsort($typeCounts);
$typeMeta = [];
foreach (array_keys($typeCounts) as $type) {
    [$icon, $scope, $label] = $scopes[$type] ?? $fallbackScope;
    $typeMeta[$type] = [
        'icon' => $icon,
        'scope' => $scope,
        'label' => $label ?? Inflector::humanize(Inflector::underscore($type ?: 'Unknown')),
    ];
}
$total = count($rows);
$addUrl = $baseurl . '/CollectionElements/add/' . $collection['id'];
?>
<style>
[data-collection-elements] .ce-chip {
    flex: 0 0 auto; display: inline-flex; align-items: center; gap: .25rem; padding: 0 .45rem; border-radius: var(--bs-border-radius-pill);
    font-size: .6875rem; font-weight: 600; line-height: 1.35rem; white-space: nowrap;
    background: var(--bs-warning-bg-subtle); color: var(--bs-warning-text-emphasis); border: 1px solid var(--bs-warning-border-subtle);
}
[data-collection-elements] .ce-chip > i { font-size: .625rem; }
[data-collection-elements] .ce-open { min-width: 0; padding: 0; border: 0; background: none; color: var(--bs-emphasis-color); text-align: start; }
[data-collection-elements] .ce-open:hover, [data-collection-elements] .ce-open:focus-visible { text-decoration: underline; }
[data-collection-elements] .ce-origin { margin-top: .15rem; font-size: .8125rem; color: var(--bs-secondary-color); }
[data-collection-elements] .ce-origin > i { margin-right: .35rem; font-size: .7rem; }
</style>

<div class="card mb-3 shadow-sm" data-collection-elements data-page-size="<?= (int)$pageSize ?>">
    <div class="p-3 border-bottom">
        <div class="d-flex align-items-center gap-3 flex-wrap">
            <div class="d-flex align-items-center gap-2 me-auto">
                <div class="rounded-2 d-flex align-items-center justify-content-center bg-primary-subtle text-primary"
                     style="width:36px;height:36px;">
                    <i class="fas fa-layer-group"></i>
                </div>
                <div>
                    <div class="fw-bold lh-1"><?= __('Elements') ?></div>
                    <div class="small text-muted mt-1">
                        <?= h(__n('%s element', '%s elements', $total, $total)) ?>
                    </div>
                </div>
            </div>

            <?php if ($total > 1): ?>
                <div class="input-group input-group-sm" style="max-width:260px;">
                    <span class="input-group-text border-end-0 bg-body">
                        <i class="fas fa-search text-muted small"></i>
                    </span>
                    <input type="search" class="form-control border-start-0 ps-0"
                           data-ce-search autocomplete="off"
                           placeholder="<?= h(__('Filter elements…')) ?>"
                           aria-label="<?= h(__('Filter elements')) ?>">
                </div>
            <?php endif; ?>

            <?php if ($canEdit): ?>
                <button type="button" class="btn btn-sm btn-primary flex-shrink-0"
                        onclick="openModal('<?= h($addUrl) ?>')"
                        title="<?= h(__('Add an element to the collection')) ?>">
                    <i class="fas fa-plus me-1"></i><?= __('Add') ?>
                </button>
            <?php endif; ?>
        </div>

        <?php if (count($typeCounts) > 1): ?>
            <div class="d-flex flex-wrap gap-1 mt-3" role="group" aria-label="<?= h(__('Filter by type')) ?>">
                <button type="button" class="btn btn-sm rounded-pill btn-primary" data-ce-type=""
                        data-ce-active="btn-primary">
                    <?= __('All') ?>
                </button>
                <?php foreach ($typeCounts as $type => $count): ?>
                    <button type="button" class="btn btn-sm rounded-pill btn-outline-secondary d-inline-flex align-items-center gap-1"
                            data-ce-type="<?= h($type) ?>"
                            data-ce-active="<?= h($this->ModalAccent->get($typeMeta[$type]['scope'])['btnClass']) ?>">
                        <i class="<?= h($typeMeta[$type]['icon']) ?>"></i>
                        <?= h($typeMeta[$type]['label']) ?>
                        <span class="opacity-75"><?= h($count) ?></span>
                    </button>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
    </div>

    <?php if ($total === 0): ?>
        <div class="card-body d-flex flex-column align-items-center text-center gap-2 py-4">
            <span class="d-inline-flex align-items-center justify-content-center rounded-circle bg-body-tertiary text-body-secondary"
                  style="width:2.5rem;height:2.5rem;">
                <i class="fas fa-box-open"></i>
            </span>
            <div class="fw-semibold"><?= __('This collection is empty') ?></div>
            <div class="text-body-secondary small">
                <?= __('Gather events, galaxy clusters, analyst data… from anywhere in MISP.') ?>
            </div>
        </div>
    <?php else: ?>
        <ul class="list-group list-group-flush overflow-auto" style="max-height:30rem;" data-ce-list></ul>
        <div class="text-center text-body-secondary small py-4 d-none" data-ce-empty>
            <i class="fas fa-filter-circle-xmark me-1 opacity-50"></i><?= __('No element matches this filter.') ?>
        </div>

        <div class="card-footer bg-body d-flex align-items-center justify-content-between gap-2 py-2 px-3 small text-body-secondary d-none"
             data-ce-footer>
            <span data-ce-status></span>
            <button type="button" class="btn btn-sm btn-link text-decoration-none p-0" data-ce-more>
                <i class="fas fa-chevron-down me-1"></i><?= __('Show more') ?>
            </button>
        </div>

        <template data-ce-row-tpl>
            <li class="list-group-item list-group-item-action d-flex align-items-center gap-3 py-2 px-3">
                <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3"
                      style="width:2.25rem;height:2.25rem;" data-ce-tile><i></i></span>
                <div class="min-w-0 flex-grow-1 lh-sm">
                    <div class="d-flex align-items-center gap-2 min-w-0" data-ce-title></div>
                    <div class="small text-body-secondary text-truncate mt-1" data-ce-meta></div>
                </div>
                <div class="d-flex align-items-center gap-1 flex-shrink-0">
                    <?php if ($canEdit): ?>
                        <a href="#" class="btn btn-sm btn-link text-danger px-1" data-ce-remove
                           title="<?= h(__('Remove from the collection')) ?>"
                           aria-label="<?= h(__('Remove from the collection')) ?>">
                            <i class="fas fa-trash-can"></i>
                        </a>
                    <?php endif; ?>
                </div>
            </li>
        </template>
        <script type="application/json" data-ce-data><?= json_encode([
            'rows' => $rows,
            'types' => $typeMeta,
            'removeUrl' => $baseurl . '/collectionElements/deleteSelection/',
            'i18n' => [
                'shown' => __('%s of %s shown'),
                'unresolved' => __('Not resolvable on this instance, or not visible to you'),
                'missing' => __('not in MISP yet'),
                'open' => __('Open'),
            ],
        ], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE) ?></script>
    <?php endif; ?>
</div>

<?php if ($total > 0): ?>
<script>
(function () {
    document.querySelectorAll('[data-collection-elements]:not([data-ce-bound])').forEach(function (card) {
        card.setAttribute('data-ce-bound', '');
        var payload = JSON.parse(card.querySelector('[data-ce-data]').textContent);
        var pageSize = parseInt(card.dataset.pageSize, 10) || 50;
        var list = card.querySelector('[data-ce-list]');
        var template = card.querySelector('[data-ce-row-tpl]');
        var search = card.querySelector('[data-ce-search]');
        var typeButtons = card.querySelectorAll('[data-ce-type]');
        var empty = card.querySelector('[data-ce-empty]');
        var footer = card.querySelector('[data-ce-footer]');
        var status = card.querySelector('[data-ce-status]');
        var more = card.querySelector('[data-ce-more]');
        var i18n = payload.i18n;
        var state = { query: '', type: '', limit: pageSize };
        var matching = [];

        payload.rows.forEach(function (row) {
            row.haystack = [row.title, row.sub, row.uuid, row.desc, row.from, row.missing ? i18n.missing : '', payload.types[row.type].label]
                .filter(Boolean).join(' ').toLowerCase();
        });

        // A standalone object has no page: it opens in the working view's popover
        function openObject(row, anchor) {
            if (!row.record || !window.IntelGraphWorking || !window.IntelGraphWorking.openObject) {
                return;
            }
            window.IntelGraphWorking.openObject({
                key: row.key, value: row.title, record: row.record, origin: row.origin,
                who: row.who, when: row.when, why: row.desc
            }, anchor, null);
        }

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

        function buildRow(row) {
            var meta = payload.types[row.type];
            var node = template.content.firstElementChild.cloneNode(true);
            var tile = node.querySelector('[data-ce-tile]');
            tile.style.background = 'rgba(var(--bs-' + meta.scope + '-rgb), .12)';
            tile.style.color = 'rgb(var(--bs-' + meta.scope + '-rgb))';
            tile.title = meta.label;
            tile.firstElementChild.className = meta.icon;

            node.setAttribute('data-ce-key', row.key);
            var label = row.title !== null ? row.title : row.uuid;
            var titleClass = row.title !== null ? 'fw-semibold text-truncate' : 'font-monospace small text-truncate';
            var title;
            if (row.record) {
                title = el('button', titleClass + ' ce-open', label);
                title.type = 'button';
                title.setAttribute('aria-haspopup', 'dialog');
                title.title = i18n.open + ': ' + label;
                title.addEventListener('click', function () { openObject(row, node); });
            } else {
                title = row.url ? el('a', titleClass + ' text-decoration-none', label) : el('span', titleClass, label);
            }
            if (row.url) {
                title.href = row.url;
            } else if (row.title === null) {
                title.classList.add('text-body-secondary');
                title.title = i18n.unresolved;
            }
            var titleLine = node.querySelector('[data-ce-title]');
            titleLine.appendChild(title);
            if (row.missing) {
                var chip = el('span', 'ce-chip', i18n.missing);
                chip.setAttribute('data-ce-missing', '');
                chip.insertBefore(el('i', 'fas fa-circle-question'), chip.firstChild).setAttribute('aria-hidden', 'true');
                titleLine.appendChild(chip);
            }

            var metaLine = node.querySelector('[data-ce-meta]');
            metaLine.appendChild(el('span', '', meta.label));
            if (row.rid !== null) {
                metaLine.appendChild(document.createTextNode(' \u00b7 '));
                metaLine.appendChild(el('span', 'fw-semibold', '#' + row.rid));
            }
            if (row.title !== null && row.uuid && !row.record) {
                metaLine.appendChild(el('span', 'font-monospace ms-2 opacity-75', row.uuid));
            }
            if (row.sub) {
                metaLine.appendChild(document.createTextNode(' \u00b7 '));
                metaLine.appendChild(el('span', '', row.sub));
            }
            if (row.desc) {
                metaLine.appendChild(document.createTextNode(' \u00b7 '));
                metaLine.appendChild(el('i', 'fas fa-comment fa-xs opacity-50 me-1'));
                var desc = el('span', 'fst-italic', row.desc);
                desc.title = row.desc;
                metaLine.appendChild(desc);
            }
            if (row.from) {
                var from = el('div', 'ce-origin text-truncate', row.from);
                from.title = row.from;
                from.setAttribute('data-ce-origin', '');
                from.insertBefore(el('i', 'fas fa-puzzle-piece'), from.firstChild).setAttribute('aria-hidden', 'true');
                metaLine.insertAdjacentElement('afterend', from);
            }
            if (row.record) {
                node.addEventListener('click', function (event) {
                    if (!event.target.closest('a, button')) {
                        openObject(row, node);
                    }
                });
            }

            var remove = node.querySelector('[data-ce-remove]');
            if (remove) {
                remove.href = payload.removeUrl + row.id;
                remove.addEventListener('click', function (event) {
                    event.preventDefault();
                    openModal(remove.href, 'md');
                });
            }
            return node;
        }

        function renderPage(from) {
            var fragment = document.createDocumentFragment();
            matching.slice(from, state.limit).forEach(function (row) {
                fragment.appendChild(buildRow(row));
            });
            list.appendChild(fragment);
            var shown = Math.min(state.limit, matching.length);
            empty.classList.toggle('d-none', matching.length !== 0);
            list.classList.toggle('d-none', matching.length === 0);
            footer.classList.toggle('d-none', matching.length <= pageSize);
            more.classList.toggle('d-none', shown >= matching.length);
            status.textContent = i18n.shown.replace('%s', shown).replace('%s', matching.length);
        }

        function apply() {
            matching = payload.rows.filter(function (row) {
                return (state.type === '' || row.type === state.type)
                    && (state.query === '' || row.haystack.indexOf(state.query) !== -1);
            });
            state.limit = pageSize;
            list.replaceChildren();
            list.scrollTop = 0;
            renderPage(0);
        }

        var debounce;
        if (search) {
            search.addEventListener('input', function () {
                clearTimeout(debounce);
                debounce = setTimeout(function () {
                    state.query = search.value.trim().toLowerCase();
                    apply();
                }, 120);
            });
        }
        typeButtons.forEach(function (button) {
            button.addEventListener('click', function () {
                state.type = button.dataset.ceType;
                typeButtons.forEach(function (other) {
                    var active = other === button;
                    other.dataset.ceActive.split(' ').forEach(function (cls) {
                        other.classList.toggle(cls, active);
                    });
                    other.classList.toggle('btn-outline-secondary', !active);
                });
                apply();
            });
        });
        more.addEventListener('click', function () {
            var from = state.limit;
            state.limit += pageSize;
            renderPage(from);
        });
        apply();
    });
})();
</script>
<?php endif; ?>
