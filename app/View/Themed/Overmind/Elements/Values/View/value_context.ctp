<?php
/**
 * What the community has labelled this value, drawn as the event
 * overview's Context card: contradictions first, then the labels sorted
 * into Attribution, Behaviour, Classification and Mitigation.
 *
 * A label reaches this card from the value's occurrences or from their
 * events; a chip's title gives each count in its own unit, since their
 * sum would count nothing. A pinned handling taxonomy shows its most
 * restrictive label and counts the others.
 *
 * Lazily loaded from ValuesController::viewContext.
 *
 * @var array $valueIntelligence
 * @var string $valueB64
 */
App::uses('EventContextTool', 'Tools/EventOverview');
App::uses('FontAwesomeHelper', 'View/Helper');

$profile = $valueIntelligence;
$taxonomies = $profile['tags'];
$galaxies = $profile['galaxies'];
$tagCap = isset($profile['tag_cap']) ? $profile['tag_cap'] : null;
// Techniques a galaxy lists before "Show N more".
$techniquesShown = 8;

// Pinned by the reader's analyst profile, and absent from this value.
$absent = array();
foreach (array('taxonomies', 'galaxies') as $kind) {
    $rows = isset($profile['absent'][$kind]) ? $profile['absent'][$kind] : array();
    foreach ($rows as $row) {
        $absent[] = array('key' => $row['key'], 'kind' => $kind);
    }
}

$conflicts = array();
$tags = array();
foreach ($taxonomies as $taxonomy) {
    if (!empty($taxonomy['conflict'])) {
        $names = array();
        foreach ($taxonomy['tags'] as $tag) {
            if (!empty($tag['conflict'])) {
                $names[] = $tag['name'];
            }
        }
        $conflicts[] = array(
            'taxonomy' => $taxonomy['taxonomy'],
            'tags' => empty($names)
                ? array_column($taxonomy['tags'], 'name')
                : $names,
        );
    }
    $rows = $taxonomy['tags'];
    if (!empty($taxonomy['lead'])) {
        $lead = $taxonomy['lead']['tag'];
        $others = array();
        foreach ($taxonomy['tags'] as $tag) {
            if ($tag['name'] !== $lead['name']) {
                $others[] = $tag['name'];
            }
        }
        $lead['_more'] = (int)$taxonomy['lead']['others'];
        $lead['_others'] = $others;
        $rows = array($lead);
    }
    if (!empty($taxonomy['scale']) && count($rows) === 1) {
        $rows[0]['_scale'] = $taxonomy['scale'];
    }
    foreach ($rows as $row) {
        $tags[] = $row;
    }
}

$tagCount = 0;
foreach ($taxonomies as $taxonomy) {
    $tagCount += count($taxonomy['tags']);
}
$clusterCount = 0;
$byRow = array(
    'attribution' => array(),
    'behaviour' => array(),
    'clusters' => array(),
    'mitigation' => array(),
);
foreach ($galaxies as $galaxy) {
    $clusterCount += count($galaxy['clusters']);
    $row = isset($galaxy['row'], $byRow[$galaxy['row']])
        ? $galaxy['row']
        : 'clusters';
    $byRow[$row][] = $galaxy;
}
$techniqueCount = 0;
foreach ($byRow['behaviour'] as $galaxy) {
    $techniqueCount += count($galaxy['clusters']);
}

/**
 * Where a label was read, each count in its own unit.
 *
 * @param int|null $occurrences
 * @param int|null $events
 * @return string
 */
$reach = function ($occurrences, $events) {
    $parts = array();
    if ($events !== null) {
        $parts[] = sprintf(
            __n(
                'On %s event this value appears in',
                'On %s events this value appears in',
                $events
            ),
            number_format($events)
        );
    }
    if ($occurrences !== null) {
        $parts[] = sprintf(
            __n(
                'On %s occurrence of this value',
                'On %s occurrences of this value',
                $occurrences
            ),
            number_format($occurrences)
        );
    }
    return implode("\n", $parts);
};

$chipOptions = array(
    'note' => function ($source) use ($reach) {
        return $reach(
            isset($source['occurrences']) ? $source['occurrences'] : null,
            isset($source['events']) ? $source['events'] : null
        );
    },
    'suffix' => function ($source) {
        $out = '';
        if (!empty($source['_scale'])) {
            $scale = $source['_scale'];
            $segments = '';
            for ($i = 1; $i <= $scale['of']; $i++) {
                $segments .= $i <= $scale['position']
                    ? '<i class="is-on"></i>'
                    : '<i></i>';
            }
            $out .= sprintf(
                '<span class="vp-scale-mini" title="%s">%s</span>',
                h(sprintf(
                    __('%1$s · %2$s (%3$s of %4$s)'),
                    $scale['label'],
                    $scale['reading'],
                    $scale['position'],
                    $scale['of']
                )),
                $segments
            );
        }
        if (!empty($source['_more'])) {
            $out .= sprintf(
                '<span class="vp-tag-more" title="%s">%s</span>',
                h(implode(', ', $source['_others'])),
                h(sprintf(
                    __n(
                        'and %s other label',
                        'and %s other labels',
                        $source['_more']
                    ),
                    number_format($source['_more'])
                ))
            );
        }
        return $out;
    },
);

/**
 * The clusters of some galaxies, as TagChip rows.
 *
 * @param array $groups
 * @return array
 */
$clusterRows = function (array $groups) {
    $out = array();
    foreach ($groups as $galaxy) {
        foreach ($galaxy['clusters'] as $cluster) {
            $out[] = array(
                'id' => $cluster['id'],
                'value' => $cluster['name'],
                'galaxy' => $galaxy['galaxy'],
                'galaxy_id' => isset($galaxy['galaxy_id'])
                    ? $galaxy['galaxy_id']
                    : null,
                'icon' => isset($galaxy['icon']) ? $galaxy['icon'] : null,
                'occurrences' => $cluster['occurrences'],
                'events' => $cluster['events'],
            );
        }
    }
    return $out;
};

/**
 * Techniques or courses of action, a list per galaxy, as the event's
 * Behaviour row draws them.
 *
 * @param array $groups
 * @return string
 */
$techniques = function (array $groups) use ($baseurl, $reach, $techniquesShown) {
    ob_start();
    foreach ($groups as $galaxy) {
        $count = count($galaxy['clusters']);
        $icon = empty($galaxy['icon']) ? '' : sprintf(
            '<i class="%s fa-%s" aria-hidden="true"></i>',
            h(FontAwesomeHelper::findNamespace($galaxy['icon'])),
            h($galaxy['icon'])
        );
        $name = empty($galaxy['galaxy_id'])
            ? '<span>' . h($galaxy['galaxy']) . '</span>'
            : sprintf(
                '<a href="%s">%s</a>',
                h($baseurl . '/galaxies/view/' . (int)$galaxy['galaxy_id']),
                h($galaxy['galaxy'])
            );
        echo '<section class="eo-tech-group">';
        printf(
            '<h6 class="eo-tech-galaxy">%s%s<small>%s</small></h6>',
            $icon,
            $name,
            $count
        );
        echo '<ul class="eo-techniques">';
        foreach ($galaxy['clusters'] as $at => $cluster) {
            $source = array('value' => $cluster['name']);
            $href = empty($cluster['id'])
                ? null
                : $baseurl . '/galaxy_clusters/view/' . (int)$cluster['id'];
            printf(
                '<li%s title="%s">%s<span class="eo-tech-id">%s</span>'
                    . '<span class="eo-tech-name">%s</span>%s</li>',
                $at >= $techniquesShown ? ' class="vp-tech-extra" hidden' : '',
                h(trim($cluster['name'] . "\n\n" . $reach(
                    $cluster['occurrences'],
                    $cluster['events']
                ))),
                $href ? '<a href="' . h($href) . '">' : '<span>',
                h((string)EventContextTool::techniqueId($source)),
                h(EventContextTool::techniqueName($source)),
                $href ? '</a>' : '</span>'
            );
        }
        echo '</ul>';
        if ($count > $techniquesShown) {
            $more = $count - $techniquesShown;
            printf(
                '<button type="button" class="vp-tech-more" data-vp-tech-more'
                    . ' aria-expanded="false" data-less="%s">%s</button>',
                h(__('Show fewer')),
                h(sprintf(
                    __n('Show %s more', 'Show %s more', $more),
                    number_format($more)
                ))
            );
        }
        echo '</section>';
    }
    return ob_get_clean();
};

$subtitle = h(sprintf(__n('%s tag', '%s tags', $tagCount), number_format($tagCount)))
    . ' · '
    . h(sprintf(
        __n('%s galaxy cluster', '%s galaxy clusters', $clusterCount),
        number_format($clusterCount)
    ));

$hasLabels = !empty($taxonomies) || !empty($galaxies);
$headerExtra = null;
if ($hasLabels) {
    $headerExtra = '<div class="input-group input-group-sm eo-filter">'
        . '<span class="input-group-text border-end-0">'
        . '<i class="fas fa-search text-muted small"></i></span>'
        . '<input type="search" class="form-control border-start-0 ps-0"'
        . ' data-vp-label-filter autocomplete="off"'
        . ' placeholder="' . h(__('Filter labels…')) . '"'
        . ' aria-label="' . h(__('Filter labels')) . '">'
        . '</div>';
}
?>
<div class="card shadow-sm mb-3 vp-panel vp-context"
     style="--vp-panel-color: var(--tag);">

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('Tags and galaxies'),
        'panelIcon' => 'misp-icon misp-icon-tag misp-simple',
        'panelColor' => 'var(--tag)',
        'panelSub' => $subtitle,
        'panelExtra' => $headerExtra,
    )) ?>

    <?php if (!$hasLabels && empty($absent)): ?>
        <div class="vp-empty">
            <i class="fas fa-tag"></i>
            <span><?= __('Nobody has tagged this value.') ?></span>
        </div>
    <?php else: ?>

        <?php if (!empty($conflicts)): ?>
            <div class="eo-tag-warnings" role="alert">
                <?php foreach ($conflicts as $conflict): ?>
                    <div class="eo-tag-warning">
                        <i class="fas fa-code-branch"></i>
                        <div class="min-w-0 eo-note-body">
                            <span class="fw-semibold"><?= h(sprintf(
                                __('The %s labels on this value contradict each other'),
                                $conflict['taxonomy']
                            )) ?></span>
                            <span class="small"><?= __('Shown as they are, not resolved to one.') ?></span>
                            <div class="eo-tag-warning-tags">
                                <?php foreach ($conflict['tags'] as $name): ?>
                                    <code><?= h($name) ?></code>
                                <?php endforeach; ?>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>

        <dl class="eo-rows">
            <dt><?= __('Attribution') ?></dt>
            <dd>
                <?php if (empty($byRow['attribution'])): ?>
                    <span class="eo-none"><i class="fas fa-user-secret"></i><?= __('None stated') ?></span>
                <?php else: ?>
                    <?= $this->TagChip->clusters($clusterRows($byRow['attribution']), $chipOptions) ?>
                <?php endif; ?>
            </dd>

            <?php if (!empty($byRow['behaviour'])): ?>
                <dt><?= __('Behaviour') ?><small><?= h(sprintf(
                    __n('%s technique', '%s techniques', $techniqueCount),
                    number_format($techniqueCount)
                )) ?></small></dt>
                <dd><?= $techniques($byRow['behaviour']) ?></dd>
            <?php endif; ?>

            <?php if (!empty($tags) || !empty($byRow['clusters']) || !empty($absent)): ?>
                <dt><?= __('Classification') ?></dt>
                <dd>
                    <div class="eo-chips">
                        <?php foreach ($absent as $row): ?>
                            <span class="eo-absent" title="<?= h($row['kind'] === 'galaxies'
                                ? __('Pinned by your analyst profile. Nothing on this value is attributed to one of its clusters.')
                                : __('Pinned by your analyst profile. Nothing on this value carries a label from it.')) ?>">
                                <i class="fas fa-thumbtack"></i><?= h($row['key']) ?> <em><?= __('not set') ?></em>
                            </span>
                        <?php endforeach; ?>
                        <?= $this->TagChip->collection($tags, $chipOptions) ?>
                        <?php if (!empty($byRow['clusters'])): ?>
                            <?= $this->TagChip->clusters($clusterRows($byRow['clusters']), $chipOptions) ?>
                        <?php endif; ?>
                    </div>
                </dd>
            <?php endif; ?>

            <?php if (!empty($byRow['mitigation'])): ?>
                <dt><?= __('Mitigation') ?></dt>
                <dd><?= $techniques($byRow['mitigation']) ?></dd>
            <?php endif; ?>
        </dl>

        <?php if ($tagCap !== null): ?>
            <div class="eo-card-foot">
                <span class="eo-legend">
                    <i class="fas fa-filter"></i>
                    <?= h(sprintf(
                        __('The %s most-carried labels. This value has more, so no taxonomy is drawn as a scale.'),
                        number_format($tagCap)
                    )) ?>
                </span>
            </div>
        <?php endif; ?>

    <?php endif; ?>

</div>
