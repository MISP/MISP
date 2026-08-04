<?php
$decodedArgs = json_decode($passedArgs, true) ?: [];
$searchall = $decodedArgs['searchall'] ?? '';

// Only used when rendered as a standalone page (ignored in the ajax fragment).
$this->set('headerTitle', __('Galaxy clusters'));

// Default clusters have no meaningful "published" state.
foreach ($list as $i => $cluster) {
    if (!empty($cluster['GalaxyCluster']['default'])) {
        $list[$i]['GalaxyCluster']['published'] = null;
    }
}

// Pagination links must carry the current context / search so in-tab reloads land on the right slice.
$paginatorUrl = [$galaxy_id];
if (!empty($context) && $context !== 'all') {
    $paginatorUrl['context'] = $context;
}
if (!empty($searchall)) {
    $paginatorUrl['searchall'] = $searchall;
}
$this->Paginator->options(['url' => $paginatorUrl]);

$showOwnerOrg = $isSiteAdmin || (Configure::read('MISP.showorgalternate') && Configure::read('MISP.showorg'));
$showCreatorOrg = $isSiteAdmin || Configure::read('MISP.showorg') || (Configure::read('MISP.showorgalternate') && Configure::read('MISP.showorg'));

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'GalaxyCluster.id',
        'enable_path' => 'GalaxyCluster.enabled',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'GalaxyCluster.id',
        'data_path' => 'GalaxyCluster.id',
        'element' => 'id',
        'url' => $baseurl . '/galaxy_clusters/view/%id%',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Distribution'),
        'data_path' => 'GalaxyCluster.distribution',
        'element' => 'distribution',
        'card_section' => 'top',
        'display_in' => ['card']
    ],
    [
        'name' => __('Name'),
        'data_path' => 'GalaxyCluster',
        'element' => 'cluster_value',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Synonyms'),
        'data_path' => 'GalaxyCluster.synonyms',
        'element' => 'synonyms',
        'card_section' => 'tag',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Owner Org'),
        'data_path' => 'Org',
        'element' => 'organisation',
        'card_section' => 'meta',
        'display_in' => ['card'],
        'requirement' => $showOwnerOrg,
    ],
    [
        'name' => __('Creator Org'),
        'data_path' => 'Orgc',
        'element' => 'organisation',
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
        'requirement' => $showCreatorOrg,
    ],
    [
        'name' => __('Default'),
        'data_path' => 'GalaxyCluster.default',
        'element' => 'default',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        // How many times this cluster's tag is used on events and attributes.
        'name' => __('#Relations'),
        'data_path' => 'GalaxyCluster',
        'element' => 'cluster_relations',
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'GalaxyCluster.id',
        'card_section' => 'extra',
        'actions' => [
            [
                'type' => 'navigate',
                'label' => __('View'),
                'icon' => 'eye',
                'url' => $baseurl . '/galaxy_clusters/view/%id%',
            ],
            [
                'type' => 'navigate',
                'label' => __('View correlation graph'),
                'icon' => 'share-nodes',
                'url' => $baseurl . '/galaxies/viewGraph/%id%',
            ],
            [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/galaxy_clusters/edit/%id%',
                'requirement' => function ($row) use ($me) {
                    return empty($row['GalaxyCluster']['default'])
                        && (!empty($me['Role']['perm_site_admin'])
                            || ($me['org_id'] == $row['GalaxyCluster']['org_id'] && !empty($me['Role']['perm_galaxy_editor'])));
                },
            ],
            [
                'type' => 'modal',
                'label' => __('Fork'),
                'icon' => 'code-branch',
                'url' => $baseurl . '/galaxy_clusters/add/%galaxy_id%/forkUuid:%uuid%',
                'url_params_data_paths' => [
                    'galaxy_id' => 'GalaxyCluster.galaxy_id',
                    'uuid' => 'GalaxyCluster.uuid',
                ],
                'requirement' => function ($row) use ($me) {
                    return !empty($me['Role']['perm_galaxy_editor']);
                },
            ],
            [
                'type' => 'modal',
                'label' => __('Contribute to misp-galaxy'),
                'icon' => 'handshake',
                'url' => $baseurl . '/galaxy_clusters/export_for_misp_galaxy/%id%',
                'requirement' => function ($row) {
                    return empty($row['GalaxyCluster']['default']);
                },
            ],
            [
                'type' => 'divider',
            ],
            [
                'type' => 'modal',
                'label' => __('Publish'),
                'icon' => 'upload text-success',
                'url' => $baseurl . '/galaxy_clusters/publish/%id%',
                'size' => 'sm',
                'requirement' => function ($row) use ($me) {
                    return empty($row['GalaxyCluster']['published'])
                        && (!empty($me['Role']['perm_site_admin'])
                            || ($me['org_id'] == $row['GalaxyCluster']['orgc_id'] && !empty($me['Role']['perm_galaxy_editor']) && !empty($me['Role']['perm_publish'])));
                },
            ],
            [
                'type' => 'modal',
                'label' => __('Restore'),
                'icon' => 'trash-arrow-up text-success',
                'url' => $baseurl . '/galaxy_clusters/restore/%id%',
                'size' => 'sm',
                'requirement' => function ($row) use ($me) {
                    return !empty($row['GalaxyCluster']['deleted'])
                        && (!empty($me['Role']['perm_site_admin']) || $me['org_id'] == $row['GalaxyCluster']['orgc_id']);
                },
            ],
            [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'class' => 'text-danger',
                'url' => $baseurl . '/galaxy_clusters/delete/%id%',
                'size' => 'lg',
                'requirement' => function ($row) use ($me) {
                    return !empty($me['Role']['perm_site_admin'])
                        || ($me['org_id'] == $row['GalaxyCluster']['org_id'] && !empty($me['Role']['perm_galaxy_editor']));
                },
            ],
        ],
    ],
];
?>

<input type="hidden" id="clusterGalaxyId" value="<?= h($galaxy_id) ?>">
<input type="hidden" id="clusterCurrentContext" value="<?= h($context) ?>">

<?php
echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $list,
            'filter_bar' => [
                'pull' => 'right',
                // Current-filter chips + "Clear all", shown even in the ajax fragment
                'active_filters' => array_filter([
                    __('Context') => (!empty($context) && $context !== 'all') ? $context : null,
                    __('Search') => $searchall !== '' ? $searchall : null,
                ]),
                'clear_url' => $baseurl . '/galaxy_clusters/index/' . $galaxy_id,
                'children' => [
                    [
                        'type' => 'search',
                        'button' => __('Search'),
                        'placeholder' => __('Search value, description, synonym or UUID'),
                        'name' => 'searchall',
                        'mode' => 'legacy',
                    ],
                    [
                        'type' => 'button',
                        'label' => __('My Clusters'),
                        'icon' => 'fas fa-user',
                        'class' => 'btn btn-primary',
                        'url' => $baseurl . '/galaxy_clusters/index/' . $galaxy_id . '/context:' . ($context === 'orgc' ? 'all' : 'orgc'),
                    ],
                    [
                        'type' => 'dropdown',
                        'label' => __('Context'),
                        'name' => 'context',
                        'options' => [
                            '' => __(''),
                            'default' => __('Default'),
                            'custom' => __('Custom'),
                            'deleted' => __('Deleted'),
                        ],
                    ],
                ],
                // Mass delete (soft/hard) via deleteSelection. delete_url is absolute because item_url carries the galaxy id.
                'delete' => ($isSiteAdmin || !empty($me['Role']['perm_galaxy_editor'])) ? '/deleteSelection' : null,
                'delete_url' => '/galaxy_clusters/deleteSelection',
            ],
            'fields' => $fields,
            'primary_id_path' => 'GalaxyCluster.id',
            'row_dblclick_url' => $baseurl . '/galaxy_clusters/view/%id%',
        ],
    ],
    'item_url' => '/galaxy_clusters/index/' . $galaxy_id,
]);
?>

<script>
/*
 * In-tab reload: this index lives inside the Galaxy view "Clusters" tab, so
 * every filter/pagination/sort interaction reloads THIS fragment in place
 * instead of navigating the whole page away to /galaxy_clusters/index.
 */
(function () {
    function clustersContainer() {
        return document.querySelector('.ajax-tab-content[data-url*="galaxy_clusters/index"]');
    }

    function loadClusters(url) {
        var c = clustersContainer();
        if (!c) return;
        c.style.opacity = '0.5';
        c.style.pointerEvents = 'none';
        fetch(url, { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
            .then(function (r) { return r.text(); })
            .then(function (html) {
                c.innerHTML = html;
                c.style.opacity = '';
                c.style.pointerEvents = '';
                c.querySelectorAll('script').forEach(function (o) {
                    var s = document.createElement('script');
                    if (o.src) { s.src = o.src; } else { s.textContent = o.textContent; }
                    document.head.appendChild(s);
                    document.head.removeChild(s);
                });
            })
            .catch(function () {
                c.style.opacity = '';
                c.style.pointerEvents = '';
            });
    }

    // Build /galaxy_clusters/index/<id>/context:<ctx>/searchall:<term>
    function buildClusterUrl(ctx) {
        var c = clustersContainer();
        if (!c) return '#';
        var gidEl = c.querySelector('#clusterGalaxyId');
        var field = c.querySelector('#filterField');
        var gid = gidEl ? gidEl.value : '';
        var term = field ? field.value.trim() : '';
        var url = baseurl + '/galaxy_clusters/index/' + gid;
        if (ctx && ctx !== 'all') url += '/context:' + encodeURIComponent(ctx);
        if (term) url += '/searchall:' + encodeURIComponent(term);
        return url;
    }

    // Context to keep on search: the dropdown value
    function currentContext() {
        var c = clustersContainer();
        var sel = c ? c.querySelector('.topbar-filter[name="context"]') : null;
        if (sel && sel.value) return sel.value;
        var hid = c ? c.querySelector('#clusterCurrentContext') : null;
        return hid ? hid.value : 'all';
    }

    // Wire the persistent container ONCE
    var c = clustersContainer();
    if (c && !c.dataset.clustersWired) {
        c.dataset.clustersWired = '1';

        // Internal navigation (context/My Clusters buttons, "Clear all", sort headers, pagination) → reload in place.
        c.addEventListener('click', function (e) {
            var a = e.target.closest('a[href]');
            if (!a) return;
            var href = a.getAttribute('href');
            if (href && href.indexOf('/galaxy_clusters/index') !== -1) {
                e.preventDefault();
                loadClusters(href);
            }
        });

        // Context dropdown — capture + stopPropagation to beat filter_bar's own window.location listener.
        c.addEventListener('change', function (e) {
            var sel = e.target.closest('.topbar-filter[name="context"]');
            if (!sel) return;
            e.stopPropagation();
            loadClusters(buildClusterUrl(sel.value));
        }, true);

        // Search button + Enter — keep the current context.
        c.addEventListener('click', function (e) {
            if (!e.target.closest('#filterButton')) return;
            e.preventDefault();
            e.stopPropagation();
            loadClusters(buildClusterUrl(currentContext()));
        }, true);
        c.addEventListener('keypress', function (e) {
            if (e.key !== 'Enter') return;
            if (!e.target.closest('#filterField')) return;
            e.preventDefault();
            e.stopPropagation();
            loadClusters(buildClusterUrl(currentContext()));
        }, true);
    }
})();
</script>
