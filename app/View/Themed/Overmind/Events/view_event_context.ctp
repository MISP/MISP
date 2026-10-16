<?php
$eventId = (int)$event['Event']['id'];
$tagOf = function (array $item) {
    return $item['kind'] === 'cluster'
        ? [(int)($item['cluster']['tag_id'] ?? 0), $item['cluster']['tag_name'] ?? null]
        : [(int)($item['tag']['Tag']['id'] ?? 0), $item['tag']['Tag']['name'] ?? null];
};
$mark = function (array $item) use ($tagOf) {
    $source = $item['kind'] === 'cluster' ? $item['cluster'] : $item['tag'];
    $source['_eo_level'] = $item['level'];
    $source['_eo_count'] = (int)$item['count'];
    list($source['_eo_tag_id'], $source['_eo_tag_name']) = $tagOf($item);
    return $source;
};
$inObjects = $inObjects ?? [];
// Opens the tab most of the carriers sit in, filtered to the label.
$onIndicators = function ($count, $only, $tagId, $tagName) use ($inObjects) {
    $label = $only
        ? __n('Only on %s indicator', 'Only on %s indicators', $count, $count)
        : __n('Also on %s indicator', 'Also on %s indicators', $count, $count);
    $inner = '<i class="misp-icon misp-icon-attribute misp-simple"></i>' . h(__('on %s', $count));
    if (empty($tagName)) {
        return sprintf('<span class="eo-on%s" title="%s">%s</span>', $only ? ' is-only' : '', h($label), $inner);
    }
    return sprintf(
        '<button type="button" class="eo-on%s" data-eo-filter-tags="%s" data-eo-filter-tab="%s" title="%s">%s</button>',
        $only ? ' is-only' : '',
        h($tagName),
        ($inObjects[$tagId] ?? 0) * 2 >= $count ? 'objects' : 'attributes',
        h($label . ' · ' . __('show them')),
        $inner
    );
};
$origin = function (array $source) {
    if (empty($source['event_id'])) {
        return '';
    }
    return $this->element('Events/View/extension_origin', [
        'event_id' => $source['event_id'],
        'compact' => true,
        'only_foreign' => true,
        'class' => 'eo-origin',
    ]);
};
$chipOptions = [
    'searchUrl' => '',
    'unitClass' => function ($source) {
        return ($source['_eo_level'] ?? '') === 'indicators' ? 'eo-ind' : '';
    },
    'suffix' => function ($source) use ($origin, $onIndicators) {
        $count = (int)($source['_eo_count'] ?? 0);
        if ($count === 0) {
            return $origin($source);
        }
        return $origin($source) . $onIndicators(
            $count,
            ($source['_eo_level'] ?? '') === 'indicators',
            $source['_eo_tag_id'] ?? 0,
            $source['_eo_tag_name'] ?? null
        );
    },
];
$tags = function (array $items) use ($mark) {
    $out = [];
    foreach ($items as $item) {
        if ($item['kind'] === 'tag') {
            $out[] = $mark($item);
        }
    }
    return $out;
};
$clusters = function (array $items) use ($mark) {
    $out = [];
    foreach ($items as $item) {
        if ($item['kind'] === 'cluster') {
            $out[] = $mark($item);
        } elseif ($item['kind'] === 'unheld') {
            $out[] = [
                'value' => $item['name'],
                'galaxy' => $item['galaxy']['name'] ?? $item['key'],
                'galaxy_id' => $item['galaxy']['id'] ?? null,
                'icon' => $item['galaxy']['icon'] ?? null,
                'tag_id' => $item['tag']['Tag']['id'] ?? null,
                'description' => __('Cluster not available here'),
                '_eo_level' => $item['level'],
                '_eo_count' => (int)$item['count'],
                '_eo_tag_id' => (int)($item['tag']['Tag']['id'] ?? 0),
                '_eo_tag_name' => $item['tag']['Tag']['name'] ?? null,
            ];
        }
    }
    return $out;
};
$techniques = function (array $items) use ($baseurl, $origin, $tagOf, $onIndicators) {
    ob_start();
    echo '<ul class="eo-techniques">';
    foreach ($items as $item) {
        $cluster = $item['cluster'];
        $only = $item['level'] === 'indicators';
        $href = !empty($cluster['id']) ? $baseurl . '/galaxy_clusters/view/' . (int)$cluster['id'] : null;
        printf(
            '<li class="%s" title="%s">%s<span class="eo-tech-id">%s</span><span class="eo-tech-name">%s</span>%s%s%s</li>',
            $only ? 'eo-ind' : '',
            h($cluster['value']),
            $href ? '<a href="' . h($href) . '">' : '<span>',
            h($item['technique'] ?? ''),
            h(EventContextTool::techniqueName($cluster)),
            $href ? '</a>' : '</span>',
            $origin($cluster),
            $item['count'] > 0
                ? $onIndicators((int)$item['count'], $only, ...$tagOf($item))
                : ''
        );
    }
    echo '</ul>';
    return ob_get_clean();
};
$byGalaxy = function (array $items) use ($baseurl, $techniques) {
    ob_start();
    foreach (EventContextTool::byGalaxy($items) as $group) {
        $galaxy = $group['galaxy'];
        $icon = empty($galaxy['icon']) ? '' : sprintf(
            '<i class="%s fa-%s" aria-hidden="true"></i>',
            h(FontAwesomeHelper::findNamespace($galaxy['icon'])),
            h($galaxy['icon'])
        );
        $name = empty($galaxy['id'])
            ? '<span>' . h($galaxy['name']) . '</span>'
            : sprintf('<a href="%s">%s</a>', h($baseurl . '/galaxies/view/' . (int)$galaxy['id']), h($galaxy['name']));
        printf(
            '<section class="eo-tech-group"><h6 class="eo-tech-galaxy">%s%s<small>%s</small></h6>%s</section>',
            $icon,
            $name,
            count($group['items']),
            $techniques($group['items'])
        );
    }
    return ob_get_clean();
};

$labelCount = 0;
foreach (['attribution', 'behaviour', 'classification', 'clusters', 'mitigation'] as $row) {
    foreach ($rows[$row] as $item) {
        $labelCount += $item['kind'] === 'absent' ? 0 : 1;
    }
}
$mayModifyTags = $this->Acl->canModifyTag($event) || !empty($isSiteAdmin);
// Anyone who may add at least a local tag may accept AI suggestions.
$aiTagsUrl = Configure::read('Plugin.AI_services_enable')
    && $this->Acl->canModifyTag($event, true)
    && $this->Acl->canAccess('events', 'aiRecommendTags')
    ? $baseurl . '/events/aiRecommendTags/' . $eventId
    : null;
$editTags = $baseurl . '/events/editEventTags/' . $eventId;
$editClusters = $baseurl . '/events/editEventGalaxies/' . $eventId;
$hasIndicatorOnly = false;
foreach ($rows as $items) {
    foreach ((array)$items as $item) {
        if (($item['level'] ?? '') === 'indicators') {
            $hasIndicatorOnly = true;
        }
    }
}
?>
<div class="eo-context">
    <div class="eo-card-head">
        <div class="misp-icon-tile eo-tile" style="--tile:var(--bs-galaxy);--tile-bg:color-mix(in srgb, var(--bs-galaxy) 12%, transparent);">
            <i class="misp-icon misp-icon-galaxy misp-simple"></i>
        </div>
        <div class="min-w-0 me-auto">
            <div class="eo-card-title"><?= __('Context') ?></div>
            <div class="eo-card-sub">
                <?php if ($profileName): ?>
                    <?php
                    $profileLink = $profileId
                        ? sprintf('<a href="%s" title="%s">%s</a>', h($baseurl . '/analystProfiles/view/' . (int)$profileId), h(__('Open your analyst profile')), h($profileName))
                        : h($profileName);
                    ?>
                    <?= __('Ordered by your %s profile', $profileLink) ?>
                    <a href="<?= h($baseurl . '/analystProfiles/index') ?>" class="eo-profile-change" title="<?= h(__('Choose another analyst profile')) ?>"><i class="fas fa-sliders"></i></a>
                <?php else: ?>
                    <?= __('Tags and galaxy clusters') ?>
                <?php endif; ?>
            </div>
        </div>
        <?php if ($labelCount > 0): ?>
            <div class="input-group input-group-sm eo-filter">
                <span class="input-group-text border-end-0"><i class="fas fa-search text-muted small"></i></span>
                <input type="search" class="form-control border-start-0 ps-0" data-eo-label-filter
                       placeholder="<?= h(__('Filter labels…')) ?>" aria-label="<?= h(__('Filter labels')) ?>" autocomplete="off">
            </div>
        <?php endif; ?>
        <div class="eo-figure"><b><?= $labelCount ?></b> <?= h(__n('label', 'labels', $labelCount)) ?></div>
    </div>

    <?php
    $conflicts = [];
    foreach (['global' => 'fas fa-globe', 'local' => 'fas fa-user'] as $scope => $scopeIcon) {
        foreach ($tagConflicts[$scope] ?? [] as $conflict) {
            $conflict['icon'] = $scopeIcon;
            $conflict['scope'] = $scope === 'local' ? __('Local tags') : __('Global tags');
            $conflicts[] = $conflict;
        }
    }
    ?>
    <?php if (!empty($conflicts) || !empty($missingTaxonomies)): ?>
        <div class="eo-tag-warnings" role="alert">
            <?php foreach ($conflicts as $conflict): ?>
                <div class="eo-tag-warning">
                    <i class="fas fa-triangle-exclamation"></i>
                    <div class="min-w-0">
                        <?php $taxonomyId = $conflict['taxonomy']['Taxonomy']['id'] ?? null; ?>
                        <span class="fw-semibold"><?= h($conflict['conflict']) ?></span>
                        <span class="eo-muted small" title="<?= h($conflict['scope']) ?>"><i class="<?= $conflict['icon'] ?> me-1"></i></span>
                        <div class="eo-tag-warning-tags">
                            <?php foreach ($conflict['tags'] as $tagName): ?>
                                <code><?= h($tagName) ?></code>
                            <?php endforeach; ?>
                            <?php if ($taxonomyId): ?>
                                <a href="<?= h($baseurl . '/taxonomies/view/' . (int)$taxonomyId) ?>" class="small"><?= __('View taxonomy') ?></a>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            <?php endforeach; ?>
            <?php if (!empty($missingTaxonomies)): ?>
                <div class="eo-tag-warning">
                    <i class="fas fa-tags"></i>
                    <div class="min-w-0">
                        <span class="fw-semibold"><?= __n('Missing a required taxonomy', 'Missing required taxonomies', count($missingTaxonomies)) ?></span>
                        <div class="eo-tag-warning-tags">
                            <?php foreach ($missingTaxonomies as $namespace): ?>
                                <code><?= h($namespace) ?></code>
                            <?php endforeach; ?>
                        </div>
                    </div>
                </div>
            <?php endif; ?>
        </div>
    <?php endif; ?>

    <dl class="eo-rows">
        <dt><?= __('Attribution') ?></dt>
        <dd>
            <?php if (empty($rows['attribution'])): ?>
                <span class="eo-none"><i class="fas fa-user-secret"></i><?= __('None stated') ?></span>
            <?php else: ?>
                <?= $this->TagChip->clusters($clusters($rows['attribution']), $chipOptions) ?>
            <?php endif; ?>
        </dd>

        <?php if (!empty($rows['behaviour'])): ?>
            <dt><?= __('Behaviour') ?><small><?= h(__n('%s technique', '%s techniques', count($rows['behaviour']), count($rows['behaviour']))) ?></small></dt>
            <dd><?= $byGalaxy($rows['behaviour']) ?></dd>
        <?php endif; ?>

        <?php if (!empty($rows['classification']) || !empty($rows['clusters'])): ?>
            <dt><?= __('Classification') ?></dt>
            <dd>
                <div class="eo-chips">
                    <?php foreach ($rows['classification'] as $item): ?>
                        <?php if ($item['kind'] === 'absent'): ?>
                            <span class="eo-absent" title="<?= h(__('Pinned by your analyst profile, not on this event')) ?>">
                                <i class="fas fa-thumbtack"></i><?= h($item['key']) ?> <em><?= __('not set') ?></em>
                            </span>
                        <?php endif; ?>
                    <?php endforeach; ?>
                    <?= $this->TagChip->collection($tags($rows['classification']), $chipOptions) ?>
                    <?php if (!empty($rows['clusters'])): ?>
                        <?= $this->TagChip->clusters($clusters($rows['clusters']), $chipOptions) ?>
                    <?php endif; ?>
                </div>
            </dd>
        <?php endif; ?>

        <?php if (!empty($rows['mitigation'])): ?>
            <dt><?= __('Mitigation') ?></dt>
            <dd><?= $byGalaxy($rows['mitigation']) ?></dd>
        <?php endif; ?>
    </dl>

    <?php if (!$rolledUp): ?>
        <div class="eo-rollup">
            <span class="eo-muted small"><?= __('Labels found on the indicators are not included yet — this event is large.') ?></span>
            <button type="button" class="btn btn-sm btn-outline-secondary" data-eo-rollup="<?= h($baseurl . '/events/viewEventContext/' . $eventId . ($extensionSuffix ?? '') . '/rollup:1') ?>">
                <?= __('Include them') ?>
            </button>
        </div>
    <?php endif; ?>

    <div class="eo-card-foot eo-actions">
        <?php if ($hasIndicatorOnly): ?>
            <span class="eo-legend"><span class="eo-legend-swatch"></span><?= __('only on indicators') ?></span>
        <?php endif; ?>
        <span class="ms-auto d-inline-flex flex-wrap justify-content-end gap-1">
            <?php if ($aiTagsUrl !== null): ?>
                <button type="button" class="btn btn-sm btn-outline-tag" data-tour="event-tags-ai"
                        onclick="openModal('<?= h($aiTagsUrl) ?>', 'lg')" title="<?= h(__('Recommend tags with AI')) ?>">
                    <i class="fas fa-robot me-1"></i><?= __('AI') ?>
                </button>
            <?php endif; ?>
            <?php if ($mayModifyTags): ?>
                <span class="btn-group btn-group-sm" role="group" aria-label="<?= h(__('Tags')) ?>">
                    <button type="button" class="btn btn-outline-tag" data-tour="event-tags-relationships"
                            onclick="openModal('<?= h($baseurl . '/events/editEventTagRelationships/' . $eventId) ?>', 'xl')"
                            title="<?= h(__('Set how this event relates to its tags')) ?>">
                        <i class="fas fa-diagram-project me-1"></i><?= __('Relationships') ?>
                    </button>
                    <button type="button" class="btn btn-tag" data-tour="event-tags-edit"
                            onclick="openModal('<?= h($editTags) ?>', 'xl')">
                        <i class="fas fa-pen-to-square me-1"></i><?= __('Edit Tags') ?>
                    </button>
                </span>
                <span class="btn-group btn-group-sm" role="group" aria-label="<?= h(__('Galaxy clusters')) ?>">
                    <button type="button" class="btn btn-outline-galaxy" data-tour="event-galaxies-relationships"
                            onclick="openModal('<?= h($baseurl . '/events/editEventGalaxyRelationships/' . $eventId) ?>', 'xl')"
                            title="<?= h(__('Set how this event relates to its clusters')) ?>">
                        <i class="fas fa-diagram-project me-1"></i><?= __('Relationships') ?>
                    </button>
                    <button type="button" class="btn btn-galaxy" data-tour="event-galaxies-edit"
                            onclick="openModal('<?= h($editClusters) ?>', 'xl')">
                        <i class="fas fa-pen-to-square me-1"></i><?= __('Edit Galaxy Clusters') ?>
                    </button>
                </span>
            <?php endif; ?>
        </span>
    </div>
</div>
