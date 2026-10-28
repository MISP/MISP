<?php
App::uses('IndexFilterDraft', 'Tools');

$filter_bar = $scaffold_data['filter_bar'] ?? null;
if (empty($filter_bar)) {
    return;
}

/*
 * Every bar is a picker bar unless it opts out with `picker_bar => false`:
 * `more_filters` selects and top-level `dropdown`s become fixed-option
 * pickers. A picker takes one value unless its child names the `separator`
 * its controller splits on (`||` for CRUD and IndexFilter parameters).
 */
$pickerBarOn = $filter_bar['picker_bar'] ?? true;
if ($pickerBarOn) {
    $toPicker = function (array $child) {
        $options = [];
        $walk = function ($list) use (&$walk, &$options) {
            foreach ((array)$list as $value => $label) {
                if (is_array($label) && isset($label['value'], $label['name'])) {
                    $value = $label['value'];
                    $label = $label['name'];
                } elseif (is_array($label)) {
                    $walk($label);
                    continue;
                }
                if ((string)$value === '') {
                    continue;
                }
                $options[] = ['value' => (string)$value, 'label' => (string)$label];
            }
        };
        $walk($child['options'] ?? []);
        return [
            'type' => 'picker',
            'name' => $child['name'],
            'label' => $child['label'] ?? $child['name'],
            'icon' => $child['icon'] ?? null,
            'options' => $options,
            'single' => empty($child['separator']),
            'separator' => $child['separator'] ?? '|',
            'exclude' => !empty($child['exclude']),
            'hint' => $child['help'] ?? null,
            'group' => $child['group'] ?? null,
        ];
    };
    $children = [];
    foreach ($filter_bar['children'] as $child) {
        $type = $child['type'] ?? '';
        if ($type === 'more_filters') {
            $selects = $child['children'] ?? [];
        } elseif ($type === 'dropdown') {
            $selects = [$child];
        } else {
            $children[] = $child;
            continue;
        }
        foreach ($selects as $select) {
            $picker = empty($select['name']) ? null : $toPicker($select);
            if (!empty($picker['options'])) {
                $children[] = $picker;
            }
        }
    }
    $filter_bar['children'] = $children;
}

// The action this bar drives — pagination/search/filter URLs are built against
// `<item_url>/<action>`. Defaults to 'index';
$filterAction = $filter_bar['action'] ?? 'index';

$currentPath = $this->request->here(false);
$currentFilters = [];

/*
 * `mode => 'event'` is the convention where every filter key is prefixed in
 * the URL (`searchemail:`, `searchpublished:`). The prefix is stripped ONLY
 * there: elsewhere a key that happens to start with "search" is just its own
 * name
 */
$searchChild = null;
foreach ($filter_bar['children'] as $child) {
    if ($child['type'] === 'search') {
        $searchChild = $child;
        break;
    }
}
$stripSearchPrefix = (($searchChild['mode'] ?? 'quickFilter') === 'event');
$cleanFilterKey = function ($key) use ($stripSearchPrefix) {
    return $stripSearchPrefix ? preg_replace('/^search/', '', $key) : $key;
};

if (preg_match('~/' . preg_quote($filterAction, '~') . '/(.+)~', $currentPath, $matches)) {
    $segments = explode('/', $matches[1]);
    foreach ($segments as $segment) {
        if (strpos($segment, ':') !== false) {
            list($key, $value) = explode(':', $segment, 2);
            $currentFilters[$cleanFilterKey($key)] = $value;
        }
    }
}


foreach (($this->request->params['named'] ?? []) as $key => $value) {
    if (is_array($value)) {
        $value = implode('||', $value);
    }
    $currentFilters[$cleanFilterKey($key)] = $value;
}

$transport = $filter_bar['transport'] ?? 'path';

if ($transport === 'query') {
    foreach (($this->request->query ?? []) as $queryKey => $queryValue) {
        if (is_string($queryValue) && $queryValue !== '') {
            $currentFilters[$queryKey] = $queryValue;
        }
    }
}

$hasActiveFilters = !empty($currentFilters);

$filterId = 'filter-bar-' . uniqid();

/*
 * A bar with `picker` children drives its filters through index-filters.js:
 * pickers apply when they close, chips and toggles are links the server has
 * already built, and the results are swapped in place.
 */
$pickers = [];
$browserStrings = null;
foreach ($filter_bar['children'] as $child) {
    if (($child['type'] ?? '') === 'picker') {
        $pickers[$child['name']] = $child;
        if (!empty($child['browser'])) {
            $browserStrings = [];
        }
        if (!empty($child['sub'])) {
            $pickers[$child['sub']['name']] = $child['sub'];
        }
    }
}
$pickerMode = $pickerBarOn || !empty($pickers);
if ($pickerMode) {
    App::uses('IndexFilterState', 'Tools');
    App::uses('IndexPicker', 'Tools');
    /*
     * The URL this bar's links start from. A bar drawn for the request's own
     * action keeps its positional arguments (`auth_keys/index/<user>`); a tab
     * whose URL is not `<item_url>/<action>` names it with `base_url`.
     */
    $filterBase = $filter_bar['base_url'] ?? null;
    if ($filterBase === null) {
        $filterBase = $baseurl . $item_url . '/' . $filterAction;
        $requestPrefix = (string)($this->request->params['prefix'] ?? '');
        $requestAction = $requestPrefix === ''
            ? $this->request->params['action']
            : preg_replace('/^' . preg_quote($requestPrefix, '/') . '_/', '', $this->request->params['action']);
        $sameAction = $requestAction === $filterAction
            && basename($item_url) === Inflector::underscore($this->request->params['controller']);
        if ($sameAction) {
            foreach (($this->request->params['pass'] ?? []) as $pass) {
                $filterBase .= '/' . rawurlencode($pass);
            }
        }
    }
    $filterState = new IndexFilterState(
        $filterBase,
        $this->request->params['named'] ?? [],
        $stripSearchPrefix ? 'search' : '',
        ($filter_bar['transport'] ?? 'path') === 'query' ? ($this->request->query ?? []) : null
    );
    echo $this->element('genericElements/assetLoader', [
        'css' => ['org-tile', 'index-filters'],
        'js' => ['index-filters'],
    ]);
    if ($browserStrings !== null) {
        echo $this->element('genericElements/assetLoader', [
            'css' => ['index-filter-browser'],
            'js' => ['index-filter-browser'],
        ]);
        $browserStrings = IndexPicker::browserStrings();
    }
}

/*
 * The advanced filters are pulled out of the bar's flex row: the button stays
 * in the row as a collapse toggle, the grid of controls and the summary that
 * runs them are rendered underneath it.
 */
$moreFiltersChild = null;
foreach ($filter_bar['children'] as $child) {
    if (($child['type'] ?? '') === 'more_filters') {
        $moreFiltersChild = $child;
        break;
    }
}

// Which URL params are *this bar's own controls* (removable) — everything else
// (e.g. searchemail: scope, positional pass-args) must never show as a
// removable chip and must survive "Clear all".
$controlKeys = [];
// Optional per-control `chip_label`, so a chip can read "Value: 8.8.8.8"
// instead of exposing the raw url key.
$controlLabels = [];
foreach (($filter_bar['children'] ?? []) as $c) {
    $ctype = $c['type'] ?? '';
    if (!empty($c['name']) && !empty($c['chip_label'])) {
        $controlLabels[$c['name']] = $c['chip_label'];
    }
    if ($ctype === 'value_match' && !empty($c['name'])) {
        $controlKeys[] = $c['name'];
    } elseif ($ctype === 'search') {
        $cmode = $c['mode'] ?? 'quickFilter';
        if ($cmode === 'event' || $cmode === 'legacy') {
            if (!empty($c['name'])) $controlKeys[] = $c['name'];
            if (!empty($c['id_field'])) $controlKeys[] = $c['id_field'];
        } else {
            $controlKeys[] = 'quickFilter';
        }
    } elseif ($ctype === 'dropdown' && !empty($c['name'])) {
        $controlKeys[] = $c['name'];
    } elseif ($ctype === 'more_filters') {
        foreach (($c['children'] ?? []) as $sub) {
            if (!empty($sub['name'])) $controlKeys[] = $sub['name'];
        }
    }
}
$paginatorKeys = ['sort', 'direction', 'page', 'limit'];

/*
 * Filters that are on but have no control in this bar — the `searchemail:`
 * behind the "My events" button. They have nowhere else to show, so the
 * panel opens itself for them; a search term does not get that treatment,
 * its own box is right there in the bar showing the term.
 */
$extraKeys = array_diff(
    array_keys(array_filter($currentFilters, function ($v) { return $v !== ''; })),
    $controlKeys,
    $paginatorKeys
);

$advId = $filterId . '-adv';

// Two counts, two jobs: the panel opens itself only when one of ITS controls
// is set, while the badge answers "is anything filtering?" — search term and
// scope included, since those stay visible with the panel folded away. The
// draft engine recomputes the badge on every change; this is the first paint.
$activeSubs = 0;
foreach (($moreFiltersChild['children'] ?? []) as $sub) {
    if (!empty($sub['name']) && isset($currentFilters[$sub['name']])
        && $currentFilters[$sub['name']] !== '') {
        $activeSubs++;
    }
}
$activeTotal = count(array_diff_key(
    array_filter($currentFilters, function ($v) { return $v !== ''; }),
    array_flip($paginatorKeys)
));

/*
 * A picker bar keeps the search and the view controls in its row; every
 * filter and toggle goes to the panel its Filters button opens. The button
 * counts what is on in there: the pickers with a value, the toggles pressed.
 */
if ($pickerMode) {
    $keysOf = function (array $child) {
        if (($child['type'] ?? '') === 'time') {
            $keys = [];
            foreach ($child['fields'] as $field) {
                $keys = array_merge($keys, [$field['name']], $field['aliases'] ?? []);
            }
            return $keys;
        }
        return array_values(array_filter([$child['name'] ?? null, $child['sub']['name'] ?? null]));
    };
    $windowItems = [];
    $toggles = [];
    $menus = [];
    $buttonGroups = [];
    foreach ($filter_bar['children'] as $child) {
        $ctype = $child['type'] ?? '';
        if (in_array($ctype, ['picker', 'time', 'value_match'], true)) {
            $windowItems[] = $child;
        } elseif ($ctype === 'button') {
            $toggles[] = $child;
        } elseif ($ctype === 'menu' && !empty($child['items'])) {
            $menus[] = $child;
        } elseif ($ctype === 'button_group') {
            $buttonGroups[] = $child;
        }
    }
    $searchKeys = array_values(array_filter([
        ($searchChild['mode'] ?? 'quickFilter') === 'quickFilter' ? 'quickFilter' : ($searchChild['name'] ?? null),
        $searchChild['id_field'] ?? null,
    ]));
    $chipScope = $filter_bar['chips']['scope'] ?? [];
    $pickerKeys = [];
    foreach ($windowItems as $child) {
        $pickerKeys = array_merge($pickerKeys, $keysOf($child));
    }
    $activeKeys = array_values(array_intersect(array_keys($filterState->filters()), $pickerKeys));
    $pressed = count(array_filter($toggles, function ($child) { return !empty($child['pressed']); }));
    $activeCount = count($activeKeys) + $pressed;
    $windowId = $filterId . '-filters';
}
?>

<div id="<?= h($filterId) ?>" class="d-flex flex-wrap align-items-center<?= $pickerMode ? ' ifp-bar' : ' gap-2' ?>"<?php
    if ($pickerMode): ?> data-ifp-bar="<?= h(json_encode([
        'base' => $filterBase,
        'prefix' => $stripSearchPrefix ? 'search' : '',
        'searchField' => ($searchChild['mode'] ?? 'quickFilter') === 'quickFilter'
            ? 'quickFilter' : ($searchChild['name'] ?? null),
        'idField' => $searchChild['id_field'] ?? null,
        'apply' => $filter_bar['apply'] ?? 'close',
        'transport' => $filter_bar['transport'] ?? 'path',
        'strings' => [
            'typeToSearch' => __('Type 2 characters to search'),
            'searching' => __('Searching…'),
            'loading' => __('Loading…'),
            'listFailed' => __('The list could not be loaded'),
            'back' => __('Back to %s'),
            'drill' => __('Choose %s'),
            'noMatch' => __('Nothing matches'),
            'more' => __('%s more: type to narrow'),
            'searchFailed' => __('The search failed'),
            'search' => __('Search'),
            'selected' => __('Selected'),
            'include' => __('Include'),
            'exclude' => __('Exclude'),
            'excluded' => __('Excluded'),
            'remove' => __('Remove'),
            'apply' => __('Apply'),
            'applyOnClose' => __('Any of these. Applies when you close the picker.'),
            'applyDraft' => __('Any of these.'),
            'allOf' => __('This link asks for events with all of these. Changing the selection here switches to any of them.'),
            'unresolved' => __('Not found on this instance'),
            'loadError' => __('The filtered list could not be loaded.'),
        ],
        'browser' => $browserStrings,
    ], JSON_UNESCAPED_UNICODE)) ?>"<?php endif; ?>>

<?php if ($pickerMode): ?>

    <?php if ($searchChild): ?>
        <?php
        $mode = $searchChild['mode'] ?? 'quickFilter';
        if ($mode === 'legacy' || $mode === 'event') {
            $searchVal = $currentFilters[$searchChild['name']] ?? null;
            if ($searchVal === null && !empty($searchChild['id_field'])) {
                $searchVal = $currentFilters[$searchChild['id_field']] ?? null;
            }
        } else {
            $searchVal = $currentFilters['quickFilter'] ?? null;
        }
        $searchVal = $searchVal !== null ? urldecode($searchVal) : '';
        ?>
        <label class="ifp-query<?= $searchVal !== '' ? ' has-value' : '' ?>" data-tour="index-search">
            <i class="fas fa-search ifp-q-icon" aria-hidden="true"></i>
            <input
                id="filterField"
                type="search"
                autocomplete="off"
                spellcheck="false"
                placeholder="<?= h($searchChild['placeholder']) ?>"
                aria-label="<?= h($searchChild['placeholder']) ?>"
                value="<?= h($searchVal) ?>"
            >
            <span class="ifp-q-end">
                <button type="button" class="ifp-q-go" data-ifp-search tabindex="-1"><span aria-hidden="true">↵</span><?= h(__('Search')) ?></button>
                <button type="button" class="ifp-q-clear" data-ifp-search-clear title="<?= h(__('Clear the search')) ?>" aria-label="<?= h(__('Clear the search')) ?>"><i class="fas fa-times" aria-hidden="true"></i></button>
                <kbd class="ifp-q-kbd" title="<?= h(__('Press / to search')) ?>">/</kbd>
            </span>
        </label>
    <?php endif; ?>

    <?php if ($windowItems || $toggles): ?>
        <button type="button" class="ifp-fbtn<?= $activeCount ? ' is-set' : '' ?>" data-ifp-filters
                aria-expanded="false" aria-controls="<?= h($windowId) ?>" data-tour="index-filters">
            <i class="fas fa-sliders" aria-hidden="true"></i>
            <span><?= h(__('Filters')) ?></span>
            <span class="badge rounded-pill bg-primary" data-ifp-swap="filters-count"
                  data-ifp-keys="<?= h(implode(' ', array_map([$filterState, 'key'], $activeKeys))) ?>"
                  data-ifp-pressed="<?= (int)$pressed ?>"<?= $activeCount ? '' : ' hidden' ?>><?= (int)$activeCount ?></span>
            <i class="fas fa-chevron-down ifp-caret" aria-hidden="true"></i>
        </button>
        <?php // Right after its button, for the Tab order: it is drawn over the results. ?>
        <?= $this->element('genericElementsBS5/IndexTable/filter_window', [
            'id' => $windowId,
            'items' => $windowItems,
            'toggles' => $toggles,
            'state' => $filterState,
            'keysOf' => $keysOf,
            'activeKeys' => $activeKeys,
            'activeCount' => $activeCount,
            'resetUrl' => $filterState->clearUrl(array_merge($chipScope, $searchKeys)),
            'currentFilters' => $currentFilters,
            'filterId' => $filterId,
        ]) ?>
    <?php endif; ?>

    <?php foreach ($menus as $child): ?>
        <div class="dropdown flex-shrink-0">
            <button type="button"
                    class="<?= h($child['class'] ?? 'ifp-fbtn') ?> dropdown-toggle"
                    data-bs-toggle="dropdown" aria-expanded="false"<?php
                    if (!empty($child['title'])): ?>
                    title="<?= h($child['title']) ?>"<?php
                    endif; ?>>
                <?php if (!empty($child['icon'])): ?>
                    <i class="<?= h($child['icon']) ?>"></i>
                <?php endif; ?>
                <?= h($child['label']) ?>
            </button>
            <ul class="dropdown-menu dropdown-menu-end">
                <?php foreach ($child['items'] as $item): ?>
                    <li>
                        <a class="dropdown-item" href="<?= h($item['url']) ?>"<?php
                           if (!empty($item['title'])): ?>
                           title="<?= h($item['title']) ?>"<?php
                           endif; ?><?php
                           if (!empty($item['onclick'])): ?>
                           onclick="<?= h($item['onclick']) ?>"<?php
                           endif; ?>>
                            <?php if (!empty($item['icon'])): ?>
                                <i class="<?= h($item['icon']) ?> fa-fw me-2"></i>
                            <?php endif; ?>
                            <?= h($item['label']) ?>
                        </a>
                    </li>
                <?php endforeach; ?>
            </ul>
        </div>
    <?php endforeach; ?>

    <div class="ifp-end" data-tour="index-view">
        <?php foreach ($buttonGroups as $child): ?>
            <div class="ifp-tools" role="group"<?php
                if (!empty($child['label'])): ?> aria-label="<?= h($child['label']) ?>"<?php
                endif; ?>>
                <?php foreach ($child['buttons'] as $groupButton): ?>
                    <?php
                    $isLink = !empty($groupButton['url']);
                    $tag = $isLink ? 'a' : 'button';
                    $name = $groupButton['title'] ?? ($groupButton['label'] ?? '');
                    $attributes = [
                        'class' => trim('ifp-tool ' . ($groupButton['class'] ?? '')),
                        'title' => $name,
                        'aria-label' => $name,
                    ];
                    if ($isLink) {
                        $attributes['href'] = $groupButton['url'];
                    } else {
                        $attributes['type'] = 'button';
                    }
                    foreach (['id', 'onclick'] as $optional) {
                        if (!empty($groupButton[$optional])) {
                            $attributes[$optional] = $groupButton[$optional];
                        }
                    }
                    $renderedAttributes = '';
                    foreach ($attributes as $attrName => $value) {
                        $renderedAttributes .= sprintf(' %s="%s"', $attrName, h($value));
                    }
                    ?>
                    <<?= $tag . $renderedAttributes ?>><i class="<?= h($groupButton['icon'] ?? 'fas fa-circle') ?>" aria-hidden="true"></i></<?= $tag ?>>
                <?php endforeach; ?>
            </div>
        <?php endforeach; ?>

        <div class="ifp-segv" role="group" aria-label="<?= h(__('View')) ?>">
            <?php if (!empty($filter_bar['view_switch'])): ?>
                <?php foreach ($filter_bar['view_switch'] as $vs): ?>
                    <a href="<?= h($vs['url']) ?>"
                       class="ifp-segv-btn<?= !empty($vs['active']) ? ' active' : '' ?>"
                       title="<?= h($vs['title'] ?? '') ?>" aria-label="<?= h($vs['title'] ?? '') ?>"<?=
                       !empty($vs['active']) ? ' aria-current="true"' : '' ?>>
                        <i class="<?= h($vs['icon']) ?>" aria-hidden="true"></i>
                    </a>
                <?php endforeach; ?>
            <?php else: ?>
                <button id="viewList" type="button" class="ifp-segv-btn active" aria-pressed="true"
                        title="<?= h(__('Table view')) ?>" aria-label="<?= h(__('Table view')) ?>">
                    <i class="fas fa-list" aria-hidden="true"></i>
                </button>
                <button id="viewCard" type="button" class="ifp-segv-btn" aria-pressed="false"
                        title="<?= h(__('Card view')) ?>" aria-label="<?= h(__('Card view')) ?>">
                    <i class="fas fa-th-large" aria-hidden="true"></i>
                </button>
            <?php endif; ?>
        </div>
    </div>


<?php else: ?>

    <?php foreach ($filter_bar['children'] as $child): ?>

        <?php if ($child['type'] === 'search'): ?>
            <?php
            // Re-populate the search box from the current URL filters —
            // read the right key so the term survives a reload (important for in-tab ajax indexes).
            $mode = $child['mode'] ?? 'quickFilter';
            if ($mode === 'legacy' || $mode === 'event') {
                $searchVal = $currentFilters[$child['name']] ?? null;
                if ($searchVal === null && !empty($child['id_field'])) {
                    $searchVal = $currentFilters[$child['id_field']] ?? null;
                }
            } else {
                $searchVal = $currentFilters['quickFilter'] ?? null;
            }
            ?>
            <div class="flex-grow-1" style="max-width: 600px">
                <div class="input-group" data-tour="index-search">
                    <input
                        class="form-control"
                        id="filterField"
                        type="text"
                        placeholder="<?= h($child['placeholder']) ?>"
                        value="<?= $searchVal !== null ? h(urldecode($searchVal)) : '' ?>"
                    >
                    <button
                        id="filterButton"
                        class="btn btn-primary"
                        type="button"
                    >
                        <i class="fas fa-search"></i>
                    </button>
                </div>
            </div>
        <?php endif; ?>

        <?php if ($child['type'] === 'value_match'): ?>
            <?= $this->element('genericElementsBS5/IndexTable/filter_value_match', [
                'child' => $child,
                'value' => urldecode((string)($currentFilters[$child['name']] ?? '')),
                'inputId' => $filterId . '-value-match',
                'picker' => false,
            ]) ?>
        <?php endif; ?>

        <?php if ($child['type'] === 'dropdown'): ?>
            <select
                class="form-select flex-shrink-0 w-auto topbar-filter"
                name="<?= h($child['name']) ?>"
                aria-label="<?= h($child['label']) ?>"
            >
                <?php foreach ($child['options'] as $value => $label): ?>
                    <option value="<?= h($value) ?>"
                        <?= (isset($currentFilters[$child['name']]) && $currentFilters[$child['name']] == $value) ? 'selected' : '' ?>>
                        <?= h($label) ?>
                    </option>
                <?php endforeach; ?>
            </select>
        <?php endif; ?>

        <?php if ($child['type'] === 'more_filters'): ?>
            <?= $this->element('genericElementsBS5/IndexTable/filter_toggle', [
                'target' => $advId,
                'label' => $child['label'],
                'count' => $activeTotal,
                'open' => ($activeSubs || $extraKeys),
            ]) ?>
        <?php endif; ?>

        <?php if ($child['type'] === 'button'): ?>
            <?= $this->element('genericElementsBS5/IndexTable/filter_button', ['child' => $child]) ?>
        <?php endif; ?>

        <?php if ($child['type'] === 'menu' && !empty($child['items'])): ?>
            <div class="dropdown flex-shrink-0">
                <button type="button"
                        class="<?= h($child['class'] ?? 'btn btn-outline-primary') ?> dropdown-toggle"
                        data-bs-toggle="dropdown" aria-expanded="false"<?php
                        if (!empty($child['title'])): ?>
                        title="<?= h($child['title']) ?>"<?php
                        endif; ?>>
                    <?php if (!empty($child['icon'])): ?>
                        <i class="<?= h($child['icon']) ?>"></i>
                    <?php endif; ?>
                    <?= h($child['label']) ?>
                </button>
                <ul class="dropdown-menu dropdown-menu-end">
                    <?php foreach ($child['items'] as $item): ?>
                        <li>
                            <a class="dropdown-item" href="<?= h($item['url']) ?>"<?php
                               if (!empty($item['title'])): ?>
                               title="<?= h($item['title']) ?>"<?php
                               endif; ?><?php
                               if (!empty($item['onclick'])): ?>
                               onclick="<?= h($item['onclick']) ?>"<?php
                               endif; ?>>
                                <?php if (!empty($item['icon'])): ?>
                                    <i class="<?= h($item['icon']) ?> fa-fw me-2"></i>
                                <?php endif; ?>
                                <?= h($item['label']) ?>
                            </a>
                        </li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>

    <?php endforeach; ?>

    <div class="ms-auto index-filter-pager">
        <?php
        if (empty($filter_bar['skip_pagination'])) {
            echo $this->element(
                'genericElementsBS5/IndexTable/pagination_nav',
                ['maxPages' => 5, 'size' => 'sm']
            );
        }
        ?>
    </div>

    <?php foreach ($filter_bar['children'] as $child): ?>
    <?php if ($child['type'] === 'button_group'): ?>
        <div class="btn-group flex-shrink-0" role="group"<?php
            if (!empty($child['label'])): ?> aria-label="<?= h($child['label']) ?>"<?php
            endif; ?>>
            <?php foreach ($child['buttons'] as $groupButton): ?>
                <?php
                    $isLink = !empty($groupButton['url']);
                    $tag = $isLink ? 'a' : 'button';
                    $attributes = [
                        'class' => $groupButton['class'] ?? 'btn btn-outline-primary',
                    ];
                    if ($isLink) {
                        $attributes['href'] = $groupButton['url'];
                    } else {
                        $attributes['type'] = 'button';
                    }
                    foreach (['id', 'title', 'onclick'] as $optional) {
                        if (!empty($groupButton[$optional])) {
                            $attributes[$optional] = $groupButton[$optional];
                        }
                    }
                    $renderedAttributes = '';
                    foreach ($attributes as $name => $value) {
                        $renderedAttributes .= sprintf(' %s="%s"', $name, h($value));
                    }
                ?>
                <<?= $tag . $renderedAttributes ?>><?php
                    if (!empty($groupButton['icon'])): ?><i class="<?= h($groupButton['icon']) ?> me-1"></i><?php
                    endif; ?><?= h($groupButton['label'] ?? '') ?></<?= $tag ?>>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>
    <?php endforeach; ?>

    <div class="btn-group" role="group" data-tour="index-view">

        <?php if (!empty($filter_bar['view_switch'])): ?>
            <!-- Custom view switch (e.g. table / JSON) — each is a link/reload, not the default client-side table/card toggle. -->
            <?php foreach ($filter_bar['view_switch'] as $vs): ?>
                <a href="<?= h($vs['url']) ?>"
                   class="btn btn-outline-primary <?= !empty($vs['active']) ? 'active' : '' ?>"
                   title="<?= h($vs['title'] ?? '') ?>">
                    <i class="<?= h($vs['icon']) ?>"></i>
                </a>
            <?php endforeach; ?>
        <?php else: ?>
            <button
                id="viewList"
                type="button"
                class="btn btn-outline-primary active"
                title="Table View"
            >
                <i class="fas fa-list"></i>
            </button>
            <button
                id="viewCard"
                type="button"
                class="btn btn-outline-primary"
                title="Card View"
            >
                <i class="fas fa-th"></i>
            </button>
        <?php endif; ?>
    </div>

<?php endif; ?>

</div>

<?php if (!empty($moreFiltersChild)): ?>
    <?php
    // The advanced controls, rendered by the shared panel
    $draftFields = [];
    foreach (($moreFiltersChild['children'] ?? []) as $sub) {
        $draftFields[] = [
            'name' => $sub['name'],
            'label' => $sub['label'] ?? $sub['name'],
            'type' => 'select',
            'options' => $sub['options'] ?? [],
            'value' => isset($currentFilters[$sub['name']])
                ? urldecode($currentFilters[$sub['name']]) : '',
            'col' => $sub['col'] ?? 3,
            'help' => $sub['help'] ?? null,
            'placeholder' => $sub['placeholder'] ?? null,
        ];
    }
    ?>
    <?= $this->element('genericElementsBS5/IndexTable/filter_panel', [
        'id' => $advId,
        'open' => ($activeSubs || $extraKeys),
        'fields' => $draftFields,
        'input_class' => 'topbar-filter',
    ]) ?>
<?php endif; ?>

<?php
// Active-filters display. An index may pass an explicit `active_filters` map
// (label => value) plus a `clear_url`.
$explicitActive = $filter_bar['active_filters'] ?? null;
$isAjaxBar = $this->request->is('ajax');

$clearViaJs = false;
if ($explicitActive !== null) {
    $activeToShow = $explicitActive;
    $clearHref = $filter_bar['clear_url'] ?? ($item_url . '/' . $filterAction);
} elseif ($isAjaxBar) {
    // In an ajax tab, only this bar's own filters are removable; 
    // "Clear all" is handled in JS so it drops them while keeping the scope.
    $activeToShow = array_intersect_key($currentFilters, array_flip($controlKeys));
    $clearHref = null;
    $clearViaJs = true;
} else {
    $activeToShow = $currentFilters;
    $clearHref = $item_url . '/' . $filterAction;
}
?>
<?php if ($pickerMode): ?>
    <?php
    // Indexes paged in PHP leave the paginator describing something else.
    $pageParams = $this->Paginator->params();
    $rowCount = count($scaffold_data['data'] ?? []);
    $pagingOk = !empty($pageParams) && (int)($pageParams['current'] ?? -1) === $rowCount
        && (int)($pageParams['pageCount'] ?? 0) > 0;
    ?>
    <div class="ifp-row">
        <span class="ifp-count" data-ifp-swap="count"><?php
            // Paged by "is there a next one" (the attribute index): no total.
            $openEnded = !empty($pageParams['nextPage'])
                && (int)($pageParams['pageCount'] ?? 0) <= (int)($pageParams['page'] ?? 1);
            if ($pagingOk && $openEnded) {
                echo sprintf(
                    __('%s shown, page %s'),
                    '<b>' . h(number_format($rowCount)) . '</b>',
                    h($pageParams['page'])
                );
            } elseif ($pagingOk) {
                echo sprintf(
                    __('%s shown, page %s of %s'),
                    '<b>' . h(number_format($rowCount)) . '</b>',
                    h($pageParams['page']),
                    h($pageParams['pageCount'])
                );
            } else {
                echo sprintf(__('%s shown'), '<b>' . h(number_format($rowCount)) . '</b>');
            }
        ?></span>
        <?= $this->element('genericElementsBS5/IndexTable/filter_chips', [
            'state' => $filterState,
            'pickers' => $pickers,
            'chips' => array_merge($filter_bar['chips'] ?? [], [
                'labels' => ($filter_bar['chips']['labels'] ?? []) + $controlLabels,
            ]),
            'searchChild' => $searchChild,
        ]) ?>
        <div class="index-filter-pager">
            <?php
            if (empty($filter_bar['skip_pagination'])) {
                echo $this->element(
                    'genericElementsBS5/IndexTable/pagination_nav',
                    ['maxPages' => 5, 'size' => 'sm']
                );
            }
            ?>
        </div>
    </div>
<?php endif; ?>
<div class="index-active-filters">
<?php // With a draft in play the chips live in its summary, buttons included. ?>
<?php if (!empty($activeToShow) && empty($moreFiltersChild) && !$pickerMode): ?>
    <div class="mt-2 d-flex align-items-center flex-wrap gap-2">

        <strong class="me-1"><?= __('Active filters') ?>:</strong>

        <?php foreach ($activeToShow as $key => $value): ?>
            <span class="badge bg-primary">
                <?= h($controlLabels[$key] ?? $key) ?>: <?= h(urldecode($value)) ?>
            </span>
        <?php endforeach; ?>

        <?php if ($clearViaJs): ?>
            <button type="button" class="filter-clear-all btn btn-sm btn-outline-danger ms-auto">
                <i class="fas fa-times"></i>
                <?= __('Clear all') ?>
            </button>
        <?php else: ?>
            <a href="<?= h($clearHref) ?>"
               class="btn btn-sm btn-outline-danger ms-auto">
                <i class="fas fa-times"></i>
                <?= __('Clear all') ?>
            </a>
        <?php endif; ?>

    </div>
<?php endif; ?>
</div>

<?php
$hasMassActions = !empty($filter_bar['delete'])
    || !empty($filter_bar['soft_delete'])
    || !empty($filter_bar['fetch'])
    || !empty($filter_bar['accept'])
    || !empty($filter_bar['discard'])
    || !empty($filter_bar['export'])
    || !empty($filter_bar['mass_edit'])
    || !empty($filter_bar['mass_tag'])
    || !empty($filter_bar['mass_local_tag'])
    || !empty($filter_bar['mass_cluster'])
    || !empty($filter_bar['mass_local_cluster'])
    || !empty($filter_bar['mass_object'])
    || !empty($filter_bar['mass_relationship'])
    || !empty($filter_bar['mass_sighting'])
    || !empty($filter_bar['mass_graph'])
    || !empty($filter_bar['enable'])
    || !empty($filter_bar['require'])
    || !empty($filter_bar['highlight'])
    || !empty($filter_bar['activate']);
?>

<?php if ($hasMassActions): ?>
<?= $this->element(
    'genericElementsBS5/IndexTable/multi_select_toolbar',
    [
        'filter_bar' => $filter_bar,
        'item_url'   => $item_url,
    ]
) ?>
<?php endif; ?>

<script>
var baseIndexUrl = "<?= h($baseurl . $item_url . '/' . $filterAction) ?>";
<?php if ($hasMassActions): ?>
var selectedItems = new Map();
<?php endif; ?>

var filterBarConfig = <?= json_encode([
    'mode'        => $searchChild['mode'] ?? 'quickFilter',
    'searchField' => $searchChild['name'] ?? 'quickFilter',
    'idField'     => $searchChild['id_field'] ?? null,
    'transport'   => $transport,
]) ?>;

(function init() {
    const filterBarEl = document.getElementById('<?= h($filterId) ?>');
    const scope = filterBarEl?.closest('.tab-pane') || document;
    // When the index is rendered inside a lazily-loaded ajax tab, keep the user in that tab
    const ajaxContainer = filterBarEl?.closest('.ajax-tab-content') || null;
    // Capture per-instance config locally
    const cfg = filterBarConfig;
    const base = baseIndexUrl;
    const itemIndexPath = '<?= h($item_url . '/' . $filterAction) ?>';

    /*
     * Only wire the table/card view toggle when it is present: indexes using a
     * custom view switch have no #viewCard and manage their own reloads, so
     * setView() must NOT run for them.
     *
     * Deferred, because setView()/isMobile() live in mispOvermind.js, which
     * this inline script does not wait for. It used to carry its own copies
     * of both — that is exactly the duplication this indirection replaces.
     */
    function setupViewToggle() {
    if (scope.querySelector('#viewCard')) {
        scope.querySelector('#viewList')?.addEventListener('click', () => setView('table', true, scope));
        scope.querySelector('#viewCard')?.addEventListener('click', () => setView('card', true, scope));

        const savedView = localStorage.getItem('indexViewMode');
        setView(savedView ? savedView : (isMobile() ? 'card' : 'table'), false, scope);

        // A narrow viewport always forces card view; otherwise defaulting to table
        function applyResponsiveView() {
            const savedView = localStorage.getItem('indexViewMode');
            setView(isMobile() ? 'card' : (savedView || 'table'), false, scope);
        }

        applyResponsiveView();

        // Re-apply whenever the viewport crosses the mobile breakpoint
        let wasMobile = isMobile();
        window.addEventListener('resize', () => {
            const nowMobile = isMobile();
            if (nowMobile !== wasMobile) {
                wasMobile = nowMobile;
                applyResponsiveView();
            }
        });
    }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', setupViewToggle);
    } else {
        setupViewToggle();
    }

    /* ── deferred apply, when the bar carries a `more_filters` control ──
     *
     * The advanced controls build a draft instead of firing a query each time
     * one of them changes. Only the URL work is local, because only this bar
     * knows about the `search` key prefix, the positional scope arguments
     * and the ajax tab that may wrap it.
     * See initIndexFilterDraft() in mispOvermind.js.
     *
     * Waiting for DOMContentLoaded matters: initTopbarFilterSelects() turns
     * these selects into TomSelects there, and wiring earlier would hook a
     * control about to grow a widget of its own.
     */
    let draft = null;

    function setupDraft() {
        if (typeof initScaffoldFilterDraft !== 'function') { return; }
        draft = initScaffoldFilterDraft(filterBarEl, {
            scope: scope,
            // By id: a tab pane can hold two scaffolded indexes, and a
            // scoped query would hand this bar its neighbour's panel.
            advId: <?= json_encode($advId) ?>,
            ajaxContainer: ajaxContainer,
            base: base,
            itemPath: itemIndexPath,
            mode: cfg.mode,
            transport: cfg.transport,
            searchField: cfg.searchField,
            idField: cfg.idField,
            // Keys this bar has a control for; anything else in the URL is a
            // scope it must keep and show, never a filter it owns.
            ownedKeys: <?= json_encode(array_values(array_unique(array_merge(
                $controlKeys,
                ['sort', 'direction', 'page', 'limit']
            ))), JSON_UNESCAPED_UNICODE) ?>,
            results: '#index-results',
            swap: ['#headerCountBadge', '.index-filter-pager', '.index-active-filters'],
            // The swapped-in results arrive in the server's default view.
            onApplied: function () {
                if (scope.querySelector('#viewCard')) {
                    setView(isMobile() ? 'card' : (localStorage.getItem('indexViewMode') || 'table'), false, scope);
                }
            },
            strings: <?= IndexFilterDraft::stringsJson() ?>,
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', setupDraft);
    } else {
        setupDraft();
    }

    // Build the filter URL from the ajax container's *current* fragment URL so
    // persistent scope survives a search/filter change. Scope can be a named
    // param (events: searchemail:x) or a positional pass arg (auth keys:
    // /index/<userId>) — both are preserved; only this bar's own controls and
    // pagination/sort are recomputed.
    function buildScopedUrl() {
        const src = (ajaxContainer && ajaxContainer.dataset.url) ? ajaxContainer.dataset.url : window.location.pathname;
        const parsed = parseIndexUrl(src, itemIndexPath);
        const positional = parsed.positional;
        // Keys are held unprefixed here and re-prefixed when the URL is built.
        const filters = {};
        Object.keys(parsed.named).forEach(key => {
            const plain = (cfg.mode === 'event' && key.indexOf('search') === 0) ? key.slice(6) : key;
            filters[plain] = parsed.named[key];
        });
        // A new search/filter resets pagination and sort.
        delete filters['page']; delete filters['sort']; delete filters['direction'];

        const ff = scope.querySelector('#filterField');
        const qv = ff ? ff.value.trim() : '';
        if (cfg.mode === 'legacy' || cfg.mode === 'event') {
            delete filters[cfg.searchField];
            if (cfg.idField) delete filters[cfg.idField];
            if (qv !== '') {
                const uuidRe = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
                const numRe = /^[0-9]+$/;
                if (cfg.idField && (uuidRe.test(qv) || numRe.test(qv))) filters[cfg.idField] = qv;
                else filters[cfg.searchField] = qv;
            }
        } else {
            delete filters['quickFilter'];
            if (qv !== '') filters['quickFilter'] = qv;
        }
        scope.querySelectorAll('.topbar-filter').forEach(el => {
            const n = el.getAttribute('name');
            if (!n) return;
            if (el.value !== '') filters[n] = el.value; else delete filters[n];
        });

        const named = {};
        Object.keys(filters).forEach(k => {
            named[(cfg.mode === 'event' ? 'search' : '') + k] = filters[k];
        });
        return formatIndexUrl(base, { positional: positional, named: named });
    }

    // Filters as a query string. Same controls as buildFilterUrl(), but the
    // values ride where a '/' survives - CakePHP reads them through
    // `$this->request->query`, which _harvestParameters() already merges.
    function buildQueryUrl() {
        const params = new URLSearchParams(window.location.search);
        // A new search resets pagination and sort.
        ['page', 'sort', 'direction'].forEach(k => params.delete(k));

        const ff = scope.querySelector('#filterField');
        const qv = ff ? ff.value.trim() : '';
        if (qv !== '') params.set(cfg.searchField, qv); else params.delete(cfg.searchField);

        scope.querySelectorAll('.topbar-filter').forEach(el => {
            const n = el.getAttribute('name');
            if (!n) return;
            if (el.value !== '') params.set(n, el.value); else params.delete(n);
        });

        const qs = params.toString();
        return base + (qs ? '?' + qs : '');
    }

    // The bar's own URL builder: query transport when asked for it, named URL
    // segments otherwise (buildFilterUrl lives in mispOvermind.js).
    function buildUrl() {
        return cfg.transport === 'query' ? buildQueryUrl() : buildFilterUrl();
    }

    function go(url) {
        if (ajaxContainer && typeof reloadAjaxTabIndex === 'function') {
            reloadAjaxTabIndex(ajaxContainer, url);
        } else {
            window.location.href = url;
        }
    }

    if (filterBarEl && filterBarEl.hasAttribute('data-ifp-bar')) {
        // index-filters.js owns the search box and every link of a picker bar.
    } else if (ajaxContainer) {
        // With a draft in play the search box goes through it, so a search
        // never reloads the index out from under half-filled advanced filters.
        scope.querySelector('#filterButton')?.addEventListener('click', () => draft ? draft.apply() : go(buildScopedUrl()));
        scope.querySelector('#filterField')?.addEventListener('keypress', (e) => { if (e.key === 'Enter') { draft ? draft.apply() : go(buildScopedUrl()); } });
        scope.querySelectorAll('.topbar-filter:not([data-manual])').forEach(el => el.addEventListener('change', () => go(buildScopedUrl())));

        // "Clear all": drop this bar's own filters but keep the scope (search
        // field + dropdowns are reset, then buildScopedUrl keeps only the scope).
        scope.querySelector('.filter-clear-all')?.addEventListener('click', (e) => {
            e.preventDefault();
            const ff = scope.querySelector('#filterField');
            if (ff) ff.value = '';
            scope.querySelectorAll('.topbar-filter').forEach(el => {
                if (el.tomselect) el.tomselect.clear(true); else el.value = '';
            });
            go(buildScopedUrl());
        });

    } else {
        scope.querySelector('#filterButton')?.addEventListener('click', () => {
            if (draft) { draft.apply(); return; }
            window.location.href = buildUrl();
        });

        scope.querySelector('#filterField')?.addEventListener('keypress', function(e) {
            if (e.key !== 'Enter') return;
            if (draft) { draft.apply(); return; }
            window.location.href = buildUrl();
        });

        scope.querySelectorAll('.topbar-filter:not([data-manual])').forEach(el => {
            el.addEventListener('change', () => {
                window.location.href = buildUrl();
            });
        });
    }

    // `value_match` controls: free text is only applied when the user asks for
    // it (search button or Enter), so a half-typed value never triggers a
    // reload. The input still carries .topbar-filter, so the URL builders pick
    // its value up like any other filter.
    function applyFilters() {
        if (draft) { draft.apply(); return; }
        if (ajaxContainer) {
            go(buildScopedUrl());
        } else {
            window.location.href = buildUrl();
        }
    }

    // Looking a value up in the list entries can take a moment on large
    // warninglists, so the control shows it is working.
    function applyValueMatch(el) {
        const btn = el?.closest('.input-group')?.querySelector('.value-match-apply');
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status"></span>';
        }
        applyFilters();
    }

    // A picker bar's value-match box is index-filters.js's.
    const valueMatchScope = filterBarEl && filterBarEl.hasAttribute('data-ifp-bar') ? document.createDocumentFragment() : scope;
    valueMatchScope.querySelectorAll('.value-match-input').forEach(input => {
        input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                applyValueMatch(input);
            }
        });
    });

    valueMatchScope.querySelectorAll('.value-match-apply').forEach(btn => {
        btn.addEventListener('click', () => applyValueMatch(btn));
    });

    valueMatchScope.querySelectorAll('.value-match-clear').forEach(btn => {
        btn.addEventListener('click', () => {
            const input = btn.closest('.input-group')?.querySelector('.value-match-input');
            if (input) {
                input.value = '';
            }
            applyFilters();
        });
    });

})();
</script>