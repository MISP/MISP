<?php
$eventId   = $event['Event']['id'];
// The extended / extending mode rides along on every URL this list builds,
// so a filter, a toggle or a page change never falls back to the atomic view.
$objectsUrl = '/events/viewObjects/' . $eventId . ($extensionSuffix ?? '');

$namedParams     = $this->request->params['named'] ?? [];
$currentDeleted  = (int)($namedParams['deleted'] ?? 0);
$currentProposal = (int)($namedParams['proposal'] ?? 0);
$currentObject   = (int)($namedParams['object'] ?? 0);
// deleted:2 is "only what holds something soft-deleted"
$toggleDeleted   = $currentDeleted ? 0 : 2;
$toggleProposal  = $currentProposal ? 0 : 1;
// The toggles keep every other filter of the tab.
App::uses('IndexFilterState', 'Tools');
$tabState = new IndexFilterState(
    $baseurl . $objectsUrl,
    array_diff_key($namedParams, array_flip(['extended', 'extending']))
);
$toggleUrl   = $tabState->url(['deleted' => $toggleDeleted ?: null]);
$proposalUrl = $tabState->url(['proposal' => $toggleProposal ?: null]);

$canEdit = isset($event)
    ? $this->Acl->canModifyEvent($event)
    : false;

// Tag/galaxy "+" buttons on object attributes follow the event's tag-modify
// rights (galaxy clusters are attached as tags, so they share the permission).
$canTagObj = isset($event)
    ? $this->Acl->canModifyTag($event)
    : false;

$_enrichmentEnabled = (bool)Configure::read('Plugin.Enrichment_services_enable');
$_cortexEnabled = (bool)Configure::read('Plugin.Cortex_services_enable');
$_mayGraph = $this->Acl->canAccess('workspaces', 'addNodes');
$_mayCollect = $this->Acl->canAccess('collectionElements', 'addElementToCollection');

// Extended / extending event view: an object can belong to any event of the
// merged set, so its card says which one and wears that event's accent.
$extensionEvents = $extensionEvents ?? [];
$inExtensionView = count($extensionEvents) > 1;

// Everything the two renderings of an object (the table row and the card)
// need to derive from it, computed once per object so the two never drift on
// rights, origin or what opens by itself.
$focusId = (int)($focusId ?? 0);
$objContext = function (array $object) use (
    $inExtensionView, $extensionEvents, $canEdit, $canTagObj, $currentProposal,
    $currentObject, $focusId, $_mayGraph
) {
    $attrs = $object['Attribute'] ?? [];
    $origin = $inExtensionView
        ? ($extensionEvents[(int)($object['event_id'] ?? 0)] ?? null)
        : null;
    $first = empty($attrs) ? null : reset($attrs);
    $hasProposal = false;
    $hasFocus = false;
    foreach ($attrs as $_a) {
        $hasProposal = $hasProposal || !empty($_a['ShadowAttribute']);
        $hasFocus = $hasFocus || (int)$_a['id'] === $focusId;
    }
    return [
        'attrs' => $attrs,
        'deleted' => !empty($object['deleted']),
        'origin' => $origin,
        'foreign' => $origin !== null && $origin['role'] !== 'self',
        // A merged object belongs to another event, whose editing and tagging
        // rights are not the same as the current event's.
        'canEdit' => $origin === null ? $canEdit : !empty($origin['mayModify']),
        'canTag' => $origin === null ? $canTagObj : !empty($origin['mayModifyTag']),
        'graphItem' => ($_mayGraph && empty($object['deleted']))
            ? ['type' => 'Object', 'uuid' => $object['uuid'], 'label' => $object['name']]
            : null,
        'headline' => $first === null ? null : [
            'relation' => (string)($first['object_relation'] ?? ''),
            'value' => (string)($first['value'] ?? ''),
        ],
        // Open from the start: the objects carrying a proposal while the
        // Proposals toggle is on, the one object a link pointed at, and the one
        // holding the attribute a focus link names.
        'expand' => ($currentProposal && $hasProposal)
            || $currentObject === (int)$object['id']
            || $hasFocus,
    ];
};

$objectChip = function ($value) use ($objects) {
    foreach ($objects as $object) {
        if ((string)$object['id'] === (string)$value) {
            return $object['name'] . ' #' . $object['id'];
        }
    }
    return '#' . $value;
};

// The attribute index's pickers, led by what only an object has. An attribute
// filter keeps the objects holding at least one matching attribute.
App::uses('AttributeFilterPanel', 'Tools');
$filterLabels = $filterLabels ?? ['org' => [], 'tag' => [], 'galaxy' => []];
$moreFilterChildren = [];
foreach (AttributeFilterPanel::children(
    [
        'categoryOptions' => $categoryOptions ?? null,
        'typeOptions' => $typeOptions ?? null,
        'orgOptions' => $orgOptions ?? null,
        'galaxyOptions' => $galaxyOptions ?? null,
    ],
    true,
    [
        ['name' => 'name', 'label' => __('Template'), 'options' => $templateOptions ?? null, 'col' => 3, 'group' => __('Object')],
        ['name' => 'meta-category', 'label' => __('Meta-category'), 'options' => $metaCategoryOptions ?? null, 'col' => 3, 'group' => __('Object')],
    ]
) as $filter) {
    // `type` takes a comma list; the others one value.
    $moreFilterChildren[] = $filter + ($filter['name'] === 'type' ? ['separator' => ','] : []);
    if ($filter['name'] === 'type') {
        $moreFilterChildren[] = [
            'type' => 'picker',
            'name' => 'tags',
            'label' => __('Tags'),
            'icon' => 'fas fa-tag',
            'source' => $baseurl . '/tags/pickerSearch',
            'single' => true,
            'resolved' => $filterLabels['tag'],
            'group' => $filter['group'],
        ];
    }
}

// The fold controls only have something to act on once the page holds an
// object, so an empty list gets no pair of dead buttons.
$foldChildren = empty($objects) ? [] : [
    [
        'type'    => 'button_group',
        'label'   => __('Expand or collapse every object'),
        'buttons' => [
            [
                'class' => 'obj-expand-all',
                'icon'  => 'fas fa-angles-down',
                'label' => __('Expand all'),
            ],
            [
                'class' => 'obj-collapse-all',
                'icon'  => 'fas fa-angles-up',
                'label' => __('Collapse all'),
            ],
        ],
    ],
];

// The rows in the objects index's shape, so its columns and its card read them.
$referencesIn = $referencesIn ?? [];
$rows = [];
foreach ($objects as $object) {
    $ctx = $objContext($object);
    $rows[] = [
        'Object' => $object + [
            'attribute_count' => count($ctx['attrs']),
            'headline' => $ctx['headline'],
        ],
        'ctx' => $ctx,
        'open' => $ctx['expand'],
    ];
}

$anySelectable = false;
foreach ($rows as $row) {
    if ($row['ctx']['canEdit'] || $row['ctx']['graphItem'] !== null) {
        $anySelectable = true;
        break;
    }
}

// The objects index's columns, less the event and its creator org.
$fields = [
    [
        'element' => 'custom',
        'class' => 'oi-col-select',
        'display_in' => ['table'],
        // Not the scaffold's select_all: that one ticks every .item-checkbox
        // of the tab, the attributes of the open objects included.
        'header_html' => $anySelectable ? sprintf(
            '<input type="checkbox" class="obj-select-all form-check-input mt-0" aria-label="%s" title="%s">',
            h(__('Select all')),
            h(__('Select all'))
        ) : '',
        'function' => function ($row) {
            $ctx = $row['ctx'];
            if (!$ctx['canEdit'] && $ctx['graphItem'] === null) {
                return '';
            }
            return sprintf(
                '<span class="d-inline-flex align-items-center checkbox-index">'
                    . '<input type="checkbox" class="obj-select form-check-input mt-0" data-object-id="%d"'
                    . ' data-can-delete="%s"%s aria-label="%s" title="%s"></span>',
                (int)$row['Object']['id'],
                $ctx['canEdit'] ? '1' : '0',
                $ctx['graphItem'] === null ? '' : ' data-graph-item="' . h(json_encode($ctx['graphItem'])) . '"',
                h(__('Select this object')),
                h(__('Select this object'))
            );
        },
    ],
    [
        'name' => __('Object'),
        'sort' => 'name',
        'class' => 'oi-col-object',
        'display_in' => ['table'],
        'element' => 'custom',
        'function' => function ($row) {
            return $this->element('Objects/index_object_cell', [
                'object' => $row['Object'],
                'open' => $row['open'],
            ]);
        },
    ],
    [
        'name' => __('References'),
        'class' => 'oi-col-refs',
        'card_section' => 'references',
        'element' => 'custom',
        'function' => function ($row, $viewMode) use ($referencesIn) {
            $object = $row['Object'];
            return $this->element('Objects/object_relationships', [
                'references' => $object['ObjectReference'] ?? [],
                'objId' => $object['id'],
                'eventId' => $object['event_id'] ?? null,
                'canEdit' => $row['ctx']['canEdit'] && !$row['ctx']['deleted'],
                'menuPrefix' => $viewMode === 'card' ? 'objCardRels' : 'objRels',
                'inbound' => $referencesIn[(int)$object['id']] ?? 0,
            ]);
        },
    ],
    [
        'name' => __('Seen'),
        'sort' => 'first_seen',
        'class' => 'oi-col-seen',
        'display_in' => ['table'],
        'element' => 'custom',
        'function' => function ($row) {
            return $this->element('Objects/index_seen', ['object' => $row['Object']]);
        },
    ],
    [
        'name' => __('Modified'),
        'sort' => 'timestamp',
        'class' => 'oi-col-modified',
        'display_in' => ['table'],
        'element' => 'custom',
        'function' => function ($row) {
            return $this->element('Objects/index_modified', ['object' => $row['Object']]);
        },
    ],
    [
        'name' => __('Analyst data'),
        'header_html' => sprintf(
            '<span title="%s"><i class="misp-icon misp-icon-analyst-note misp-simple"></i></span>',
            h(__('Analyst data'))
        ),
        'class' => 'oi-col-analyst',
        'card_section' => 'analyst',
        'element' => 'analyst_data_badges',
        'note_path' => 'Object.Note',
        'opinion_path' => 'Object.Opinion',
        'relationship_path' => 'Object.Relationship',
        'relationship_inbound_path' => 'Object.RelationshipInbound',
        'uuid_path' => 'Object.uuid',
        'object_type' => 'Object',
    ],
    [
        'element' => 'custom',
        'class' => 'oi-col-actions',
        'card_section' => 'actions',
        'function' => function ($row) use ($_mayGraph, $_mayCollect, $_enrichmentEnabled) {
            return $this->element('Objects/object_row_actions', [
                'object' => $row['Object'],
                'canEdit' => $row['ctx']['canEdit'],
                'mayGraph' => $_mayGraph,
                'mayCollect' => $_mayCollect,
                'enrichmentEnabled' => $_enrichmentEnabled,
            ]);
        },
    ],
    // A card opens on the attribute list, as the objects index's cards do.
    [
        'display_in' => ['card'],
        'card_section' => 'attributes',
        'element' => 'custom',
        'function' => function ($row) use ($_enrichmentEnabled, $_cortexEnabled) {
            return '<div class="oi-card">' . $this->element('Objects/object_attribute_list', [
                'attrs' => $row['ctx']['attrs'],
                'canEdit' => $row['ctx']['canEdit'],
                'canTag' => $row['ctx']['canTag'],
                'enrichmentEnabled' => $_enrichmentEnabled,
                'cortexEnabled' => $_cortexEnabled,
            ]) . '</div>';
        },
    ],
];
$columnCount = count(array_filter($fields, function ($field) {
    return empty($field['display_in']) || in_array('table', $field['display_in'], true);
}));

$hasFilters = !empty(array_diff_key(
    $namedParams,
    array_flip(['extended', 'extending', 'page', 'sort', 'direction', 'limit', 'focus'])
));
$indexData = ['data' => [
    'data' => $rows,
    'fields' => $fields,
    'table_class' => 'oi-table',
    'card_element' => 'Objects/index_card_tile',
    'cards_per_row' => ['' => 1, 'lg' => 2, 'xxl' => 3],
    'empty_message' => $hasFilters
        ? __('No object matches these filters.')
        : __('No objects in this event.'),
    'row_class_callable' => function ($row) {
        $classes = [];
        if ($row['open']) {
            $classes[] = 'oi-open';
        }
        if ($row['ctx']['deleted']) {
            $classes[] = 'oi-deleted';
        }
        if ($row['ctx']['foreign']) {
            $classes[] = 'evt-extension-row';
        }
        return implode(' ', $classes);
    },
    'row_style_callable' => function ($row) {
        if (!$row['ctx']['foreign']) {
            return '';
        }
        return sprintf(
            '--extension-tint:%s;--extension-accent:%s;',
            $row['ctx']['origin']['palette']['sectionBg'],
            $row['ctx']['origin']['palette']['badgeBorder']
        );
    },
    'row_marker_callable' => function ($row) use ($inExtensionView) {
        if (!$inExtensionView) {
            return '';
        }
        return $this->element('Events/View/extension_band', [
            'event_id' => $row['Object']['event_id'] ?? 0,
        ]);
    },
    // The attribute table under each object, open or not.
    'row_after_callable' => function ($row) use ($columnCount, $_mayGraph, $_enrichmentEnabled, $_cortexEnabled) {
        return $this->element('Objects/object_index_detail', [
            'object' => $row['Object'],
            'ctx' => $row['ctx'],
            'columns' => $columnCount,
            'mayGraph' => $_mayGraph,
            'enrichmentEnabled' => $_enrichmentEnabled,
            'cortexEnabled' => $_cortexEnabled,
        ]);
    },
]];
?>

<div id="objectListContainer" class="container-fluid px-0" data-ifp-scope="<?= h($objectsUrl) ?>">

    <!-- ── Filter bar, as the scaffold draws it ──── -->
    <div class="ifp-card">
        <?= $this->element(
            'genericElementsBS5/IndexTable/filter_bar',
            [
                'scaffold_data' => [
                    // For the count beside the chips.
                    'data' => $objects,
                    'filter_bar' => [
                        'base_url' => $baseurl . $objectsUrl,
                        'chips' => [
                            'labels' => [
                                'deleted' => __('Deleted'),
                                'proposal' => __('Proposals'),
                                'name' => __('Template'),
                                'object' => __('Object'),
                            ],
                            'values' => [
                                'deleted' => ['1' => __('included'), '2' => __('only')],
                                'proposal' => ['1' => __('only')],
                                'object' => $objectChip,
                            ],
                        ],
                        'children' => array_merge([
                            [
                                'type'        => 'search',
                                'button'      => __('Search'),
                                'placeholder' => __('Filter objects…'),
                                'mode'        => 'legacy',
                                'name'        => 'searchFor',
                            ],
                            [
                                'type'  => 'button',
                                'url'   => $proposalUrl,
                                'class' => 'btn obj-proposal-toggle '. ($currentProposal ? 'btn-warning' : 'btn-outline-warning'),
                                'id'    => 'obj-proposal-toggle',
                                'icon'  => 'fas fa-comment-dots',
                                'label' => __('Proposals'),
                                'count' => (int)($proposalCount ?? 0),
                                'pressed' => (bool)$currentProposal,
                            ],
                            [
                                'type'  => 'button',
                                'url'   => $toggleUrl,
                                'class' => 'btn obj-deleted-toggle '. ($currentDeleted ? 'btn-danger' : 'btn-outline-danger'),
                                'id'    => 'obj-deleted-toggle',
                                'icon'  => 'fas fa-trash',
                                'label' => __('Deleted'),
                                'count' => (int)($deletedCount ?? 0),
                                'pressed' => (bool)$currentDeleted,
                            ],
                        ], $moreFilterChildren, $foldChildren),
                    ],
                ],
                'item_url' => $objectsUrl,
            ]
        ) ?>
        <div id="objMultiSelectToolbar"
             class="ms-float d-none" role="region" aria-label="<?= h(__('Selected objects')) ?>">
            <div class="p-2 border rounded bg-light d-flex align-items-center gap-2 flex-wrap">
                <span class="ms-count" id="objSelectedCount"
                      data-one="<?= h(__('%s object selected')) ?>"
                      data-many="<?= h(__('%s objects selected')) ?>"></span>
                <span class="ms-sep" aria-hidden="true"></span>
                <button id="obj-multi-graph-button"
                        class="btn btn-analystGraph btn-sm d-none"
                        type="button"
                        title="<?= __('Add the selected to the active workspace') ?>"
                        aria-label="<?= __('Add the selected to the active workspace') ?>">
                    <span class="misp-icon misp-icon-analyst-graph misp-simple text-white"></span>
                    <span class="text-white"> <?= __('Workspace') ?></span>
                </button>
                <button id="obj-multi-delete-button"
                        class="btn btn-outline-danger btn-sm d-none"
                        type="button"
                        title="<?= __('Delete selected objects') ?>"
                        aria-label="<?= __('Delete selected objects') ?>">
                    <i class="fas fa-trash"></i>
                    <span> <?= __('Delete') ?></span>
                </button>
                <span class="ms-sep" aria-hidden="true"></span>
                <button id="obj-clear-selection-button" type="button" class="btn btn-sm btn-link ms-clear">
                    <?= __('Clear selection') ?>
                </button>
            </div>
        </div>
        <?php if ($canEdit || $_mayGraph): ?>
        <div id="multiSelectToolbar"
             class="ms-float d-none" role="region" aria-label="<?= h(__('Selected attributes')) ?>">
            <div class="p-2 border rounded bg-light d-flex align-items-center gap-2 flex-wrap">
                <span class="ms-count" id="selectedCount"
                      data-one="<?= h(__('%s attribute selected')) ?>"
                      data-many="<?= h(__('%s attributes selected')) ?>"></span>
                <span class="ms-sep" aria-hidden="true"></span>
                <?php if ($_mayGraph): ?>
                <button id="mass-graph-button"
                        class="btn btn-analystGraph btn-sm d-none"
                        type="button"
                        title="<?= __('Add the selected to the active workspace') ?>"
                        aria-label="<?= __('Add the selected to the active workspace') ?>"
                        onclick="addSelectedToGraph(this)">
                    <span class="misp-icon misp-icon-analyst-graph misp-simple text-white"></span>
                    <span class="text-white"> <?= __('Workspace') ?></span>
                </button>
                <?php endif; ?>
                <?php if ($canEdit): ?>
                <button id="multi-delete-button"
                        class="btn btn-outline-danger btn-sm d-none"
                        type="button"
                        title="<?= __('Delete selected attributes') ?>"
                        aria-label="<?= __('Delete selected attributes') ?>"
                        onclick="multiSelectItems(baseurl + '/attributes/deleteSelection', '')">
                    <i class="fas fa-trash"></i>
                    <span> <?= __('Delete') ?></span>
                </button>
                <?php endif; ?>
                <span class="ms-sep" aria-hidden="true"></span>
                <button type="button" class="btn btn-sm btn-link ms-clear" onclick="clearMultiSelect(this)">
                    <?= __('Clear selection') ?>
                </button>
            </div>
        </div>
        <?php endif; ?>
    </div>

    <!-- ── Objects, laid out as the objects index ──────── -->
    <div class="oi-index">
        <div class="card shadow-sm mb-4">
            <div class="card-body p-0">
                <div id="objTableView">
                    <?= $this->element('genericElementsBS5/IndexTable/index_table', [
                        'scaffold_data' => $indexData,
                    ]) ?>
                </div>
                <div id="objCardView" class="d-none">
                    <?= $this->element('genericElementsBS5/IndexTable/index_card', [
                        'scaffold_data' => $indexData,
                    ]) ?>
                </div>
            </div>
        </div>
    </div>

    <?php if (!empty($objects)): ?>
        <?= $this->element('genericElementsBS5/IndexTable/pagination_bottom', [
            'rows' => count($objects),
        ]) ?>
    <?php endif; ?>

</div><!-- /#objectListContainer -->

<script>
(function () {
    var eventId      = <?= json_encode((string)$eventId) ?>;
    var errMsg       = <?= json_encode(__('Could not load objects.')) ?>;
    var _objBase     = baseurl + <?= json_encode($objectsUrl) ?>;

    // Correct the baseIndexUrl set by filter_bar (it appended /index)
    baseIndexUrl = _objBase;

    function getContainer() {
        return document.querySelector('.ajax-tab-content[data-url*="viewObjects"]');
    }

    // The tab's URL is its filter state (index-filters.js), minus the page.
    function buildObjectsUrl() {
        var cont = getContainer();
        var url = (cont && cont.dataset.url) || _objBase;
        return url.replace(/\/page:[^/?]*/, '');
    }

    function loadObjects(url) {
        var container = getContainer();
        if (!container) return;
        container.style.opacity       = '0.5';
        container.style.pointerEvents = 'none';
        fetch(url, { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
            .then(function (r) { return r.text(); })
            .then(function (html) {
                container.innerHTML       = html;
                container.dataset.url        = url;
                container.style.opacity      = '';
                container.style.pointerEvents = '';
                container.querySelectorAll('script').forEach(function (oldScript) {
                    var newScript = document.createElement('script');
                    if (oldScript.src) {
                        newScript.src = oldScript.src;
                    } else {
                        newScript.textContent = oldScript.textContent;
                    }
                    document.head.appendChild(newScript);
                    document.head.removeChild(newScript);
                });
                if (typeof initTopbarFilterSelects === 'function') {
                    initTopbarFilterSelects(container);
                }
                container.dispatchEvent(new CustomEvent('misp:container-loaded', {
                    bubbles: true, detail: { url: url }
                }));
                // Only a list that starts above the screen scrolls, clear of the fixed navbar.
                var top = container.getBoundingClientRect().top;
                if (top < 56) {
                    window.scrollTo({ top: Math.max(0, top + window.pageYOffset - 64), behavior: 'smooth' });
                }
            })
            .catch(function () {
                container.style.opacity      = '';
                container.style.pointerEvents = '';
                showMessage('fail', errMsg);
            });
    }

    // Expose a reload API (mirrors window.mispView.attrs) so the edit-tag /
    // edit-galaxy modals can refresh this tab after saving.
    window.mispView = window.mispView || {};
    window.mispView.objects = Object.assign(window.mispView.objects || {}, {
        loadFn:  loadObjects,
        buildFn: buildObjectsUrl
    });

    var container = getContainer();

    // The filter bar wires its search box, its panel and its Apply button
    // itself (initScaffoldFilterDraft); all this tab says is "the URLs are mine".
    if (container) {
        container.__indexFilterOverride = {
            buildUrl: buildObjectsUrl,
            reload: function (url) { loadObjects(url); return true; },
        };
    }


    // Both views draw every object, so its two toggles move together.
    function setObjectOpen(id, open) {
        if (!window.ObjectsIndex) return;
        objScope().querySelectorAll('.oi-index [data-oi-expand="' + id + '"]').forEach(function (button) {
            window.ObjectsIndex.setOpen(button, open);
        });
    }

    function setAllObjectsExpanded(expand) {
        if (!window.ObjectsIndex) return;
        objScope().querySelectorAll('.oi-index [data-oi-expand]').forEach(function (button) {
            window.ObjectsIndex.setOpen(button, expand);
        });
    }

    // The open objects survive a reload of the event view — a modal form
    // (adding a note, editing an attribute) comes back through a full page
    // load. Kept per event, for this browser tab only.
    var _openKey = 'misp.openObjects.' + eventId;
    function readOpenObjects() {
        try { return JSON.parse(sessionStorage.getItem(_openKey) || '[]'); } catch (e) { return []; }
    }
    function writeOpenObjects(ids) {
        try { sessionStorage.setItem(_openKey, JSON.stringify(ids)); } catch (e) {}
    }
    // On the fragment's own root, which an ajax reload replaces, so the
    // listener never stacks up.
    var listRoot = objScope().querySelector('#objectListContainer');
    if (listRoot) {
        listRoot.addEventListener('oi:toggle', function (e) {
            var id = e.detail.id;
            var ids = readOpenObjects().filter(function (x) { return x !== id; });
            if (e.detail.open) ids.push(id);
            writeOpenObjects(ids);
            setObjectOpen(id, e.detail.open);
        });
    }
    readOpenObjects().forEach(function (id) { setObjectOpen(id, true); });

    [['.obj-expand-all', true], ['.obj-collapse-all', false]].forEach(function (pair) {
        var btn = (container || document).querySelector(pair[0]);
        if (!btn) return;
        btn.addEventListener('click', function () {
            setAllObjectsExpanded(pair[1]);
        });
    });

    // Object mass-select. Deliberately not `.item-checkbox`: that class feeds
    // the global selectedItems map, which the attribute toolbar deletes through
    // /attributes/deleteSelection — and since an object id and an attribute id
    // are both plain integers, the two selections would silently merge.
    var objSelected = new Map();

    function objScope() { return container || document; }

    function objGraphItems() {
        var items = [];
        objSelected.forEach(function (sel) { if (sel.graphItem) items.push(sel.graphItem); });
        return items;
    }

    function updateObjToolbar() {
        var all = objScope().querySelector('.obj-select-all');
        if (all) {
            var boxes = Array.from(objScope().querySelectorAll('#objTableView .obj-select'));
            all.checked = boxes.length > 0 && boxes.every(function (box) { return box.checked; });
        }
        var bar = objScope().querySelector('#objMultiSelectToolbar');
        if (!bar) return;
        bar.classList.toggle('d-none', objSelected.size === 0);
        var countEl = objScope().querySelector('#objSelectedCount');
        if (countEl) setMultiSelectCount(countEl, objSelected.size);
        var canDeleteAll = true;
        objSelected.forEach(function (sel) { if (!sel.canDelete) canDeleteAll = false; });
        var delBtn = objScope().querySelector('#obj-multi-delete-button');
        if (delBtn) delBtn.classList.toggle('d-none', !canDeleteAll);
        var graphBtn = objScope().querySelector('#obj-multi-graph-button');
        if (graphBtn) graphBtn.classList.toggle('d-none', !window.IntelGraphActions || objGraphItems().length === 0);
        syncMultiSelectFloat();
    }

    // Both views render a checkbox per object and both are in the DOM at once,
    // so a tick has to reach the other view's copy — otherwise switching views
    // shows a selection that disagrees with the toolbar.
    function setObjSelected(id, checked, box) {
        if (checked) {
            var graphItem = null;
            try { graphItem = box.dataset.graphItem ? JSON.parse(box.dataset.graphItem) : null; } catch (e) { /* left out */ }
            objSelected.set(id, { canDelete: box.dataset.canDelete === '1', graphItem: graphItem });
        } else {
            objSelected.delete(id);
        }
        objScope().querySelectorAll('.obj-select[data-object-id="' + id + '"]')
            .forEach(function (twin) { twin.checked = checked; });
        updateObjToolbar();
    }

    // Bound per checkbox rather than delegated: the container outlives an ajax
    // reload, so a delegated listener would stack up and keep a stale Map.
    objScope().querySelectorAll('.obj-select').forEach(function (box) {
        box.addEventListener('change', function () {
            setObjSelected(box.dataset.objectId, box.checked, box);
        });
    });

    var objSelectAll = objScope().querySelector('.obj-select-all');
    if (objSelectAll) {
        objSelectAll.addEventListener('change', function () {
            var checked = objSelectAll.checked;
            objScope().querySelectorAll('#objTableView .obj-select').forEach(function (box) {
                if (box.checked !== checked) setObjSelected(box.dataset.objectId, checked, box);
            });
            updateObjToolbar();
        });
    }

    var objDelBtn = objScope().querySelector('#obj-multi-delete-button');
    if (objDelBtn) {
        objDelBtn.addEventListener('click', function () {
            if (objSelected.size === 0) return;
            openModal(
                baseurl + '/objects/deleteSelection/'
                    + JSON.stringify(Array.from(objSelected.keys()).map(Number)),
                'md'
            );
        });
    }

    var objGraphBtn = objScope().querySelector('#obj-multi-graph-button');
    if (objGraphBtn) {
        objGraphBtn.addEventListener('click', function () {
            var items = objGraphItems();
            if (items.length && window.IntelGraphActions) window.IntelGraphActions.add(items, objGraphBtn);
        });
    }

    var objClearBtn = objScope().querySelector('#obj-clear-selection-button');
    if (objClearBtn) {
        objClearBtn.addEventListener('click', function () {
            Array.from(objSelected.keys()).forEach(function (id) { setObjSelected(id, false); });
        });
    }

    // The delete modal lives outside this fragment; this is how it tells the
    // index which rows it managed to remove.
    window.objIndexSelection = {
        clear: function (ids) {
            (ids || []).forEach(function (id) { objSelected.delete(String(id)); });
            updateObjToolbar();
        }
    };

    updateObjToolbar();

    // View switch (list <-> cards). mispOvermind.js binds #viewList/#viewCard on
    // DOMContentLoaded against #tableView/#cardView — neither the buttons nor
    // those containers exist yet in a lazily loaded tab, which is why the
    // toggle did nothing here. So this fragment owns its own, scoped to its
    // container: the two button ids repeat in every tab's filter bar.
    function applyObjView(mode, animate) {
        var scope = container || document;
        var list = scope.querySelector('#objTableView');
        var cards = scope.querySelector('#objCardView');
        if (!list || !cards) return;
        var showCards = mode === 'card';
        list.classList.toggle('d-none', showCards);
        cards.classList.toggle('d-none', !showCards);
        var btnList = scope.querySelector('#viewList');
        var btnCard = scope.querySelector('#viewCard');
        if (btnList) btnList.classList.toggle('active', !showCards);
        if (btnCard) btnCard.classList.toggle('active', showCards);
        if (animate && typeof animateIndexView === 'function') {
            animateIndexView(showCards ? cards : list);
        }
    }

    // Own storage key: 'indexViewMode' drives the scaffold indexes, and an
    // object card is a different trade-off from an attribute card.
    [['#viewList', 'table'], ['#viewCard', 'card']].forEach(function (pair) {
        var btn = container ? container.querySelector(pair[0]) : null;
        if (!btn) return;
        var fresh = btn.cloneNode(true);
        btn.parentNode.replaceChild(fresh, btn);
        fresh.addEventListener('click', function () {
            try { localStorage.setItem('objectsViewMode', pair[1]); } catch (e) {}
            applyObjView(pair[1], true);
        });
    });

    var _savedObjView = 'table';
    try { _savedObjView = localStorage.getItem('objectsViewMode') || 'table'; } catch (e) {}
    applyObjView(_savedObjView, false);

    (container || document).querySelectorAll('.obj-attr-actions, .obj-row-actions, .oi-refs-toggle').forEach(function (toggle) {
        bootstrap.Dropdown.getOrCreateInstance(toggle, {
            popperConfig: { strategy: 'fixed' }
        });
    });

})();
</script>
