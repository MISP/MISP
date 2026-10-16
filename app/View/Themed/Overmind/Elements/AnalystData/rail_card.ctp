<?php
/*
 * The Analyst data card of a detail page's rail: an "Add a note" launcher
 * with opinion and relationship beside it, and the thread attached to the
 * record under it.
 *
 * Params:
 *   $objectType : the record's type (GalaxyCluster, EventReport, Note, …)
 *   $objectUuid : the record's uuid
 *   $showThread : draw the thread (default true); a page whose main column
 *                 already shows it passes false and keeps the launcher only
 */
App::uses('ClassRegistry', 'Utility');
App::uses('DistributionLevel', 'Tools');

$objectType = $objectType ?? '';
$objectUuid = $objectUuid ?? '';
$showThread = !isset($showThread) || $showThread;
if ($objectType === '' || $objectUuid === '') {
    return;
}

$canAdd = !empty($me['Role']['perm_analyst_data']);
$thread = $showThread
    ? ClassRegistry::init('Note')->fetchThreadForObject($me, $objectType, $objectUuid)
    : ['Note' => [], 'Opinion' => [], 'Relationship' => [], 'RelationshipInbound' => []];

$newestFirst = function ($a, $b) {
    return strcmp($b['item']['created'] ?? '', $a['item']['created'] ?? '')
        ?: (int)$b['item']['id'] - (int)$a['item']['id'];
};
$talk = [];
$links = [];
foreach (['Note', 'Opinion'] as $type) {
    foreach ($thread[$type] as $item) {
        $talk[] = ['type' => $type, 'item' => $item];
    }
}
foreach ($thread['Relationship'] as $item) {
    $links[] = ['type' => 'Relationship', 'item' => $item];
}
foreach ($thread['RelationshipInbound'] as $item) {
    $links[] = ['type' => 'RelationshipInbound', 'item' => $item];
}
usort($talk, $newestFirst);
usort($links, $newestFirst);

if (empty($talk) && empty($links) && !$canAdd) {
    return;
}

$countTree = function (array $items) use (&$countTree) {
    $n = 0;
    foreach ($items as $item) {
        $n += 1 + $countTree($item['Note'] ?? []) + $countTree($item['Opinion'] ?? []);
    }
    return $n;
};
$total = $countTree($thread['Note']) + $countTree($thread['Opinion'])
    + $countTree($thread['Relationship']) + count($thread['RelationshipInbound']);

$css = (array)$this->get('additionalCss');
$js = (array)$this->get('additionalJs');
if (!in_array('analyst-rail', $css, true)) {
    $this->set('additionalCss', array_merge($css, ['analyst-rail']));
}
if (!in_array('analyst-rail', $js, true)) {
    $this->set('additionalJs', array_merge($js, ['analyst-rail']));
}

$visibleTalk = 3;
$visibleLinks = max(1, 4 - min($visibleTalk, count($talk)));

$selfNouns = [
    'GalaxyCluster' => __('this cluster'),
    'Galaxy' => __('this galaxy'),
    'EventReport' => __('this report'),
    'SharingGroup' => __('this sharing group'),
    'Collection' => __('this collection'),
    'Event' => __('this event'),
    'Attribute' => __('this attribute'),
    'Object' => __('this object'),
    'Note' => __('this note'),
    'Opinion' => __('this opinion'),
    'Relationship' => __('this relationship'),
];
$selfNoun = $selfNouns[$objectType] ?? __('this record');

$targets = [
    'Event' => ['icon' => 'misp-icon misp-icon-event misp-simple', 'label' => 'info', 'path' => '/events/view/'],
    'Attribute' => ['icon' => 'misp-icon misp-icon-attribute misp-simple', 'label' => 'value', 'path' => '/attributes/view/'],
    'Object' => ['icon' => 'misp-icon misp-icon-object misp-simple', 'label' => 'name', 'path' => '/objects/view/'],
    'GalaxyCluster' => ['icon' => 'misp-icon misp-icon-galaxy misp-simple', 'label' => 'value', 'path' => '/galaxy_clusters/view/'],
    'Galaxy' => ['icon' => 'misp-icon misp-icon-galaxy misp-simple', 'label' => 'name', 'path' => '/galaxies/view/'],
    'EventReport' => ['icon' => 'misp-icon misp-icon-report misp-simple', 'label' => 'name', 'path' => '/event_reports/view/'],
    'SharingGroup' => ['icon' => 'misp-icon misp-icon-sharing-group misp-simple', 'label' => 'name', 'path' => '/sharing_groups/view/'],
    'Collection' => ['icon' => 'fas fa-layer-group', 'label' => 'name', 'path' => '/collections/view/'],
];

$addUrl = function ($type) use ($baseurl, $objectType, $objectUuid) {
    return $baseurl . '/analystData/add/' . $type . '/' . rawurlencode($objectUuid) . '/' . $objectType;
};

$ago = function ($created) {
    $seconds = time() - strtotime((string)$created);
    if ($seconds < 60) {
        return __('just now');
    }
    $minutes = intdiv($seconds, 60);
    if ($minutes < 60) {
        return __('%s min ago', $minutes);
    }
    $hours = intdiv($minutes, 60);
    if ($hours < 24) {
        return __('%s h ago', $hours);
    }
    $days = intdiv($hours, 24);
    if ($days < 30) {
        return __('%s d ago', $days);
    }
    if ($days < 365) {
        return __('%s mo ago', intdiv($days, 30));
    }
    return __('%s yr ago', intdiv($days, 365));
};

$initials = function ($name) {
    $words = preg_split('/\s+/u', trim(preg_replace('/[^\p{L}\p{N} ]/u', ' ', (string)$name)), -1, PREG_SPLIT_NO_EMPTY);
    if (empty($words)) {
        return '?';
    }
    preg_match_all('/./u', $words[0], $first);
    $letters = isset($words[1])
        ? $first[0][0] . preg_replace('/^(.).*$/us', '$1', $words[1])
        : implode('', array_slice($first[0], 0, 2));
    return strtoupper($letters);
};

$stance = function ($score) {
    $v = max(0, min(100, (int)$score));
    if ($v <= 20) {
        return [__('Strongly disagree'), 'neg', $v];
    }
    if ($v <= 40) {
        return [__('Disagree'), 'neg', $v];
    }
    if ($v <= 60) {
        return [__('Neutral'), 'mid', $v];
    }
    if ($v <= 80) {
        return [__('Agree'), 'pos', $v];
    }
    return [__('Strongly agree'), 'pos', $v];
};

$gauge = function ($score) use ($stance) {
    list($label, $tone, $v) = $stance($score);
    $offset = abs($v - 50);
    if ($v === 50) {
        $mark = '<span class="adr-gauge-dot"></span>';
    } else {
        $side = $v > 50 ? 'left' : 'right';
        $mark = sprintf('<span class="adr-gauge-fill adr-gauge-%s" style="width:%d%%"></span>', $side, $offset);
    }
    return sprintf(
        '<div class="adr-stance adr-tone-%s" title="%s">'
        . '<span class="adr-gauge" aria-hidden="true"><span class="adr-gauge-mid"></span>%s</span>'
        . '<span class="adr-stance-label">%s</span><span class="adr-stance-score">%d</span></div>',
        $tone, h(__('%s, %s out of 100', $label, $v)), $mark, h($label), $v
    );
};

$button = function ($icon, $label, $url, $class = 'adr-act', $size = null) {
    return sprintf(
        '<button type="button" class="%s" title="%s" aria-label="%s" data-adr-open="%s"%s><i class="%s" aria-hidden="true"></i></button>',
        $class, h($label), h($label), h($url), $size ? ' data-adr-size="' . h($size) . '"' : '', h($icon)
    );
};

$actions = function ($item, $type, $nested) use ($canAdd, $baseurl, $button) {
    if (!$canAdd || empty($item['uuid'])) {
        return '';
    }
    $buttons = [];
    if ($type === 'Note' || $type === 'Opinion') {
        $base = $baseurl . '/analystData/add/%s/' . rawurlencode($item['uuid']) . '/' . $type;
        $buttons[] = $button('misp-icon misp-icon-analyst-note misp-simple', $type === 'Note' ? __('Reply with a note') : __('Add a note on this opinion'), sprintf($base, 'Note'));
        $buttons[] = $button('misp-icon misp-icon-analyst-opinion misp-simple', $type === 'Note' ? __('Add an opinion on this note') : __('Add an opinion on this opinion'), sprintf($base, 'Opinion'));
    }
    if (!empty($item['_canEdit']) && !empty($item['id'])) {
        $buttons[] = $button('fas fa-pen', __('Edit'), $baseurl . '/analystData/edit/' . $type . '/' . (int)$item['id']);
        $buttons[] = $button('fas fa-trash-can', __('Delete'), $baseurl . '/analystData/delete/' . $type . '/' . (int)$item['id'], 'adr-act adr-act-danger', 'sm');
    }
    if (empty($buttons)) {
        return '';
    }
    return '<div class="adr-acts' . ($nested ? ' adr-acts-nested' : '') . '" role="group" aria-label="' . h(__('Actions')) . '">'
        . implode('', $buttons) . '</div>';
};

$meta = function ($item) use ($ago) {
    $dist = DistributionLevel::get(isset($item['distribution']) ? $item['distribution'] : null);
    $org = $item['Orgc']['name'] ?? '';
    return sprintf(
        '<div class="adr-meta"><span class="adr-org" title="%1$s">%1$s</span>'
        . '<span class="adr-author" title="%2$s">%2$s</span>'
        . '<span class="adr-time" title="%3$s">%4$s</span>'
        . '<span class="adr-dist" role="img" title="%5$s" aria-label="%5$s"><i class="%6$s" aria-hidden="true"></i></span></div>',
        h($org), h($item['authors'] ?? ''), h($item['created'] ?? ''), h($ago($item['created'] ?? '')),
        h($dist['label']), h($dist['icon'])
    );
};

$target = function ($type, $uuid, $resolved) use ($targets, $baseurl) {
    $spec = $targets[$type] ?? null;
    $record = $resolved[$type] ?? null;
    if (in_array($type, ['Note', 'Opinion', 'Relationship'], true) && !empty($uuid)) {
        return sprintf(
            '<a class="adr-target" href="%s"><span class="adr-target-label">%s</span></a>',
            h($baseurl . '/analystData/view/' . $type . '/' . $uuid), h($type)
        );
    }
    if ($spec === null || empty($record['id'])) {
        return sprintf(
            '<span class="adr-target adr-target-bare" title="%1$s">%2$s <span class="font-monospace">%3$s</span></span>',
            h($uuid), h($type), h(substr((string)$uuid, 0, 8))
        );
    }
    $label = $record[$spec['label']] ?? $type;
    return sprintf(
        '<a class="adr-target" href="%s" title="%s"><i class="adr-target-ico %s" aria-hidden="true"></i><span class="adr-target-label">%s</span></a>',
        h($baseurl . $spec['path'] . $record['id']), h($label), h($spec['icon']), h($label)
    );
};

$relationship = function ($item, $inbound) use ($target, $selfNoun) {
    $verb = '<span class="adr-verb">' . h(str_replace(['-', '_'], ' ', $item['relationship_type'] ?? 'related-to')) . '</span>';
    $self = '<span class="adr-self">' . h($selfNoun) . '</span>';
    $resolved = $item['related_object'] ?? [];
    $other = $inbound
        ? $target($item['object_type'] ?? '', $item['object_uuid'] ?? '', $resolved)
        : $target($item['related_object_type'] ?? '', $item['related_object_uuid'] ?? '', $resolved);
    $sentence = $inbound ? "$other $verb $self" : "$self $verb $other";
    return '<p class="adr-rel"><i class="fas fa-diagram-project adr-rel-ico" aria-hidden="true"></i>' . $sentence . '</p>';
};

$entry = function ($type, $item, $depth, $hidden = false) use (&$entry, $meta, $gauge, $actions, $relationship, $initials) {
    $nested = $depth > 0;
    $inbound = $type === 'RelationshipInbound';
    $clamp = $nested ? '' : ' adr-clamp';
    $body = '';
    if ($type === 'Note') {
        $body .= '<p class="adr-text' . $clamp . '" dir="auto">' . h($item['note'] ?? '') . '</p>';
    } elseif ($type === 'Opinion') {
        $body .= $gauge($item['opinion'] ?? 50);
        if (($item['comment'] ?? '') !== '') {
            $body .= '<p class="adr-text' . $clamp . '" dir="auto">' . h($item['comment']) . '</p>';
        }
    } else {
        $body .= $relationship($item, $inbound);
    }

    $children = [];
    foreach (['Note', 'Opinion'] as $childType) {
        foreach ($item[$childType] ?? [] as $child) {
            $children[] = ['type' => $childType, 'item' => $child];
        }
    }
    usort($children, function ($a, $b) {
        return strcmp($a['item']['created'] ?? '', $b['item']['created'] ?? '')
            ?: (int)$a['item']['id'] - (int)$b['item']['id'];
    });
    $replies = '';
    if (!empty($children)) {
        $list = '<ul class="adr-replies"' . ($nested ? '' : ' hidden') . '>';
        foreach ($children as $child) {
            $list .= $entry($child['type'], $child['item'], $depth + 1);
        }
        $list .= '</ul>';
        if ($nested) {
            $replies = $list;
        } else {
            $orgs = array_slice(array_unique(array_map(function ($c) {
                return $c['item']['Orgc']['name'] ?? '';
            }, $children)), 0, 3);
            $faces = '';
            foreach ($orgs as $org) {
                $faces .= '<span class="adr-face" title="' . h($org) . '">' . h($initials($org)) . '</span>';
            }
            $label = __n('%s reply', '%s replies', count($children), count($children));
            $replies = '<div class="adr-replies-wrap">'
                . '<button type="button" class="adr-replies-toggle" aria-expanded="false" data-adr-replies'
                . ' data-adr-label="' . h($label) . '" data-adr-label-open="' . h(__('Hide replies')) . '">'
                . '<span class="adr-faces" aria-hidden="true">' . $faces . '</span>'
                . '<span class="adr-replies-label">' . h($label) . '</span>'
                . '<i class="fas fa-chevron-down adr-replies-ico" aria-hidden="true"></i></button>'
                . $list . '</div>';
        }
    }

    $org = $item['Orgc']['name'] ?? '';
    return sprintf(
        '<li class="adr-entry%s adr-kind-%s"%s><span class="adr-avatar" aria-hidden="true" title="%s">%s</span>'
        . '<div class="adr-main">%s%s%s%s</div></li>',
        ($nested ? ' adr-entry-nested' : '') . ($hidden ? ' adr-more' : ''),
        strtolower($type), $hidden ? ' hidden' : '', h($org), h($initials($org)),
        $meta($item), $body, $actions($item, $inbound ? 'Relationship' : $type, $nested), $replies
    );
};

$hiddenCount = max(0, count($talk) - $visibleTalk) + max(0, count($links) - $visibleLinks);
$isEmpty = empty($talk) && empty($links);
?>
<section class="card shadow-sm mb-3 adr-card<?= $isEmpty ? ' adr-card-empty' : '' ?>" aria-label="<?= __('Analyst data') ?>"
    data-adr-read-more="<?= h(__('Read more')) ?>" data-adr-read-less="<?= h(__('Read less')) ?>">
    <?php if ($canAdd): ?>
        <div class="adr-composer">
            <button type="button" class="adr-field" data-adr-open="<?= h($addUrl('Note')) ?>">
                <i class="misp-icon misp-icon-analyst-note misp-simple adr-field-ico" aria-hidden="true"></i>
                <span class="adr-field-ph"><?= __('Add a note…') ?></span>
            </button>
            <?= $button('misp-icon misp-icon-analyst-opinion misp-simple', __('Add an opinion'), $addUrl('Opinion'), 'adr-side adr-side-opinion') ?>
            <?= $button('fas fa-diagram-project', __('Add a relationship'), $addUrl('Relationship'), 'adr-side adr-side-rel') ?>
        </div>
    <?php else: ?>
        <div class="adr-head">
            <span class="adr-head-tile" aria-hidden="true"><i class="fas fa-comment-dots"></i></span>
            <span class="adr-head-title"><?= __('Analyst data') ?></span>
            <span class="adr-head-count"><?= (int)$total ?></span>
        </div>
    <?php endif; ?>

    <?php if (!$isEmpty): ?>
        <div class="adr-thread">
            <?php if (!empty($talk)): ?>
                <ul class="adr-list">
                    <?php foreach ($talk as $i => $t): ?>
                        <?= $entry($t['type'], $t['item'], 0, $i >= $visibleTalk) ?>
                    <?php endforeach; ?>
                </ul>
            <?php endif; ?>
            <?php if (!empty($links)): ?>
                <ul class="adr-list adr-links" aria-label="<?= __('Relationships') ?>">
                    <?php foreach ($links as $i => $t): ?>
                        <?= $entry($t['type'], $t['item'], 0, $i >= $visibleLinks) ?>
                    <?php endforeach; ?>
                </ul>
            <?php endif; ?>
        </div>
        <?php if ($hiddenCount > 0): ?>
            <div class="adr-foot">
                <button type="button" class="adr-expand" aria-expanded="false" data-adr-expand
                    data-adr-label="<?= h(__('Show %s more', $hiddenCount)) ?>" data-adr-label-open="<?= h(__('Show less')) ?>">
                    <span class="adr-expand-label"><?= __('Show %s more', $hiddenCount) ?></span>
                    <i class="fas fa-chevron-down adr-expand-ico" aria-hidden="true"></i>
                </button>
                <button type="button" class="adr-all" data-adr-open="<?= h($baseurl . '/analystData/viewForObject/' . $objectType . '/' . rawurlencode($objectUuid)) ?>">
                    <?= __('Full thread') ?>
                    <span class="adr-all-count"><?= (int)$total ?></span>
                </button>
            </div>
        <?php endif; ?>
    <?php endif; ?>
</section>
