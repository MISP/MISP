<?php
/*
 * Review and publish a collection shared beyond its organisation: what goes
 * out together when it is published, and how far the investigation went.
 *
 * Set by CollectionsController::publish():
 *   $collection    array  unwrapped, with Orgc
 *   $publishState  array  Collection::workspaceSummaries()'s
 *   $review        array  Collection::publishReview()
 *   $reviewers     array  user id => email
 */
App::uses('CakeTime', 'Utility');

$uid = 'col-publish-' . dechex(mt_rand());
$accent = $this->ModalAccent->get('success');
$reviewers = $reviewers ?? [];
$withheld = !empty($publishState['withheld']);
$lastPublished = empty($collection['last_published']) ? 0 : strtotime($collection['last_published']);
$analysis = (int)($collection['analysis'] ?? 0);

$ago = function ($when) {
    $stamp = is_numeric($when) ? (int)$when : strtotime((string)$when);
    return $stamp ? CakeTime::timeAgoInWords($stamp, ['end' => '+100 years', 'accuracy' => ['year' => 'year', 'month' => 'month', 'week' => 'week', 'day' => 'day', 'hour' => 'hour', 'minute' => 'minute']]) : '';
};

// type => [glyph, scope colour (a --bs-<scope>-rgb triplet), label]
$types = [
    'Event' => ['misp-icon misp-icon-event misp-simple', 'event', __('Event')],
    'Attribute' => ['misp-icon misp-icon-attribute misp-simple', 'attribute', __('Attribute')],
    'Object' => ['misp-icon misp-icon-object misp-simple', 'object', __('Object')],
    'GalaxyCluster' => ['misp-icon misp-icon-galaxy misp-simple', 'galaxy', __('Galaxy cluster')],
    'AttributeValue' => ['misp-icon misp-icon-value-intelligence misp-simple', 'valueIntelligence', __('Value')],
    'Collection' => ['fas fa-folder', 'primary', __('Collection')],
];
$type = function ($name) use ($types) {
    return $types[$name] ?? ['fas fa-cube', 'secondary', (string)$name];
};
$tile = function ($glyph, $scope) {
    return sprintf(
        '<span class="cpr-tile" style="background:rgba(var(--bs-%1$s-rgb),.12);color:rgb(var(--bs-%1$s-rgb));" aria-hidden="true"><i class="%2$s"></i></span>',
        h($scope),
        h($glyph)
    );
};
$name = function (array $end) {
    if ($end['label'] !== null && $end['label'] !== '') {
        return '<span class="fw-semibold text-truncate">' . h($end['label']) . '</span>';
    }
    return '<span class="fst-italic text-body-secondary text-truncate" title="' . h((string)$end['address']) . '">'
        . h(__('Not visible to you')) . '</span>';
};

$member = function (array $item, $verb) use ($type, $tile, $name, $ago, $reviewers) {
    list($glyph, $scope, $label) = $type($item['type']);
    $meta = array_merge([$label], array_slice($item['meta'] ?? [], 0, 2));
    if (!empty($item['user_id']) && isset($reviewers[$item['user_id']])) {
        $meta[] = __('by %s', $reviewers[$item['user_id']]);
    }
    return '<li class="cpr-row">' . $tile($glyph, $scope)
        . '<div class="cpr-body"><div class="d-flex min-w-0">' . $name($item) . '</div>'
        . '<div class="cpr-meta text-truncate">' . h(implode(' · ', $meta)) . '</div></div>'
        . (empty($item['at']) ? '' : '<span class="cpr-when" title="' . h($verb . ' ' . $item['at']) . '">' . h($ago($item['at'])) . '</span>')
        . '</li>';
};
$graph = function (array $item) use ($tile, $ago) {
    $meta = [__n('%s node', '%s nodes', (int)$item['node_count'], (int)$item['node_count'])];
    if (!empty($item['Orgc']['name'])) {
        $meta[] = $item['Orgc']['name'];
    }
    return '<li class="cpr-row">' . $tile('misp-icon misp-icon-analyst-graph misp-simple', 'analystGraph')
        . '<div class="cpr-body"><div class="fw-semibold text-truncate">' . h($item['name']) . '</div>'
        . '<div class="cpr-meta text-truncate">' . h(implode(' · ', $meta)) . '</div></div>'
        . '<span class="cpr-when" title="' . h(__('Saved %s', $item['modified'])) . '">' . h($ago($item['modified'])) . '</span>'
        . '</li>';
};
$link = function (array $item) use ($type, $name, $ago) {
    $end = function (array $end) use ($type, $name) {
        list($glyph, $scope) = $type($end['type']);
        return '<span class="cpr-end"><i class="' . h($glyph) . '" style="color:rgb(var(--bs-' . h($scope) . '-rgb));" aria-hidden="true"></i>' . $name($end) . '</span>';
    };
    return '<li class="cpr-row cpr-link">'
        . '<div class="cpr-body d-flex align-items-center gap-2 min-w-0">' . $end($item['from'])
        . '<span class="cpr-rel">' . h($item['relationship_type'] ?: __('related')) . '<i class="fas fa-arrow-right-long ms-1" aria-hidden="true"></i></span>'
        . $end($item['to']) . '</div>'
        . '<span class="cpr-when" title="' . h(__('Drawn %s', $item['modified'])) . '">' . h($ago($item['modified'])) . '</span>'
        . '</li>';
};

$sections = [
    ['added', __('Members added'), 'fas fa-circle-plus text-success', function ($item) use ($member) { return $member($item, __('Added')); }],
    ['removed', __('Members removed'), 'fas fa-circle-minus text-danger', function ($item) use ($member) { return $member($item, __('Removed')); }],
    ['graphs', __('Saved graphs'), 'misp-icon misp-icon-analyst-graph misp-simple', $graph],
    ['relationships', __('Links between members'), 'fas fa-link', $link],
];
$total = 0;
foreach ($sections as $section) {
    $total += (int)$review[$section[0]]['count'];
}
$opened = false;
$narrower = $review['narrower'] ?? ['count' => 0, 'items' => []];
$narrowerCount = (int)$narrower['count'];

ob_start();
?>
<style>
.cpr-box { border: 1px solid var(--bs-border-color); border-radius: .5rem; overflow: hidden; }
.cpr-sec + .cpr-sec { border-top: 1px solid var(--bs-border-color); }
.cpr-head { display: flex; align-items: center; gap: .6rem; padding: .55rem .85rem; font-size: .85rem; }
summary.cpr-head { cursor: pointer; list-style: none; }
summary.cpr-head::-webkit-details-marker { display: none; }
summary.cpr-head:hover { background: var(--bs-tertiary-bg); }
summary.cpr-head:focus-visible { outline: 2px solid var(--misp-accent, var(--bs-primary)); outline-offset: -2px; }
.cpr-chev { color: var(--bs-secondary-color); font-size: .7rem; transition: transform .15s; }
.cpr-sec[open] .cpr-chev { transform: rotate(180deg); }
.cpr-sec.is-empty .cpr-head { color: var(--bs-secondary-color); }
.cpr-sec.is-empty .cpr-head::after { content: ""; width: .7rem; }
.cpr-count { margin-left: auto; min-width: 1.6rem; padding: .1rem .45rem; border-radius: 999px; background: var(--bs-secondary-bg); font-size: .72rem; font-weight: 600; text-align: center; }
.cpr-sec.has-items .cpr-count { background: rgba(var(--bs-success-rgb), .14); color: var(--bs-success-text-emphasis); }
.cpr-list { list-style: none; margin: 0; padding: 0; max-height: 15rem; overflow-y: auto; border-top: 1px solid var(--bs-border-color-translucent); }
.cpr-row { display: flex; align-items: center; gap: .65rem; padding: .45rem .85rem; min-width: 0; }
.cpr-row + .cpr-row { border-top: 1px solid var(--bs-border-color-translucent); }
.cpr-tile { flex: none; display: inline-flex; align-items: center; justify-content: center; width: 1.85rem; height: 1.85rem; border-radius: .45rem; font-size: .85rem; }
.cpr-body { flex: 1 1 auto; min-width: 0; line-height: 1.25; font-size: .82rem; }
.cpr-meta { color: var(--bs-secondary-color); font-size: .72rem; margin-top: .1rem; }
.cpr-when { flex: none; color: var(--bs-secondary-color); font-size: .7rem; white-space: nowrap; }
.cpr-end { display: inline-flex; align-items: center; gap: .35rem; min-width: 0; flex: 1 1 0; }
.cpr-end > i { flex: none; font-size: .8rem; }
.cpr-rel { flex: none; padding: .05rem .5rem; border-radius: 999px; background: rgba(var(--bs-analystData-rgb), .1); color: rgb(var(--bs-analystData-rgb)); font-size: .7rem; font-weight: 600; white-space: nowrap; }
.cpr-more { padding: .4rem .85rem; border-top: 1px solid var(--bs-border-color-translucent); color: var(--bs-secondary-color); font-size: .72rem; }
.cpr-quiet { padding: .9rem; border: 1px dashed var(--bs-border-color); border-radius: .5rem; color: var(--bs-secondary-color); font-size: .8rem; text-align: center; }
.cpr-choices { display: grid; grid-template-columns: 1fr 1fr; gap: .5rem; }
.cpr-choice { display: flex; gap: .6rem; align-items: flex-start; padding: .6rem .75rem; border: 1px solid var(--bs-border-color); border-radius: .5rem; cursor: pointer; transition: border-color .12s, background-color .12s; }
.cpr-choice:hover { background: var(--bs-tertiary-bg); }
.cpr-choice:has(input:checked) { border-color: rgba(var(--bs-success-rgb), .6); background: rgba(var(--bs-success-rgb), .07); }
.cpr-choice:has(input:focus-visible) { outline: 2px solid var(--misp-accent, var(--bs-primary)); outline-offset: 1px; }
.cpr-choice .form-check-input { flex: none; margin-top: .15rem; }
.cpr-choice-title { display: block; font-size: .85rem; font-weight: 600; }
.cpr-choice-hint { display: block; color: var(--bs-secondary-color); font-size: .72rem; line-height: 1.3; margin-top: .1rem; }
.cpr-narrow { margin-top: .6rem; border: 1px solid var(--bs-warning-border-subtle); border-radius: .5rem; overflow: hidden; }
.cpr-narrow-head { display: flex; align-items: flex-start; gap: .6rem; padding: .55rem .85rem; background: var(--bs-warning-bg-subtle); color: var(--bs-warning-text-emphasis); font-size: .82rem; line-height: 1.35; }
.cpr-narrow-head > i { flex: none; margin-top: .15rem; }
.cpr-narrow-hint { display: block; font-weight: 400; font-size: .75rem; margin-top: .1rem; }
.cpr-narrow .cpr-list { border-top-color: var(--bs-warning-border-subtle); max-height: 10rem; }
@media (max-width: 575.98px) { .cpr-choices { grid-template-columns: 1fr; } .cpr-when { display: none; } }
</style>

<div>
    <?= $this->element('genericElementsBS5/Forms/section_label', [
        'accent' => $accent['key'],
        'label' => __('Going out together'),
        'badge' => $total > 0 ? __n('%s change', '%s changes', $total, $total) : '',
        'class' => 'mb-2',
    ]) ?>
    <?php if ($total === 0): ?>
        <div class="cpr-quiet">
            <i class="fas fa-circle-info me-1 opacity-75"></i>
            <?= $lastPublished
                ? h(__('No member, graph or link changed since the last publish. Publishing shares the collection’s details and status as they are now.'))
                : h(__('Nothing in it yet: partners receive its name, description and status.')) ?>
        </div>
    <?php else: ?>
        <div class="cpr-box" data-collection-review>
            <?php foreach ($sections as $section):
                list($key, $title, $glyph, $render) = $section;
                $count = (int)$review[$key]['count'];
                $items = $review[$key]['items'];
                $open = $count > 0 && !$opened;
                $opened = $opened || $open;
            ?>
                <?php if ($count === 0): ?>
                    <div class="cpr-sec is-empty" data-review-section="<?= h($key) ?>">
                        <div class="cpr-head">
                            <i class="<?= h($glyph) ?> opacity-50" aria-hidden="true"></i>
                            <span><?= h($title) ?></span>
                            <span class="cpr-count">0</span>
                        </div>
                    </div>
                <?php else: ?>
                    <details class="cpr-sec has-items" data-review-section="<?= h($key) ?>"<?= $open ? ' open' : '' ?>>
                        <summary class="cpr-head">
                            <i class="<?= h($glyph) ?>" aria-hidden="true"></i>
                            <span class="fw-semibold"><?= h($title) ?></span>
                            <span class="cpr-count"><?= h($count) ?></span>
                            <i class="fas fa-chevron-down cpr-chev" aria-hidden="true"></i>
                        </summary>
                        <ul class="cpr-list">
                            <?php foreach ($items as $item): ?>
                                <?= $render($item) ?>
                            <?php endforeach; ?>
                        </ul>
                        <?php if ($count > count($items)): ?>
                            <div class="cpr-more"><?= h(__('and %s more', $count - count($items))) ?></div>
                        <?php endif; ?>
                    </details>
                <?php endif; ?>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>
    <?php if ($narrowerCount > 0): ?>
        <div class="cpr-narrow" data-review-narrower>
            <div class="cpr-narrow-head">
                <i class="fas fa-triangle-exclamation" aria-hidden="true"></i>
                <span>
                    <span class="fw-semibold"><?= h(__n(
                        '%s value is held in MISP only by events shared more narrowly than this collection.',
                        '%s values are held in MISP only by events shared more narrowly than this collection.',
                        $narrowerCount,
                        $narrowerCount
                    )) ?></span>
                    <span class="cpr-narrow-hint"><?= h(__('Publishing sends them to everyone this collection reaches.')) ?></span>
                </span>
            </div>
            <ul class="cpr-list">
                <?php foreach ($narrower['items'] as $item): ?>
                    <?= $member($item, '') ?>
                <?php endforeach; ?>
            </ul>
            <?php if ($narrowerCount > count($narrower['items'])): ?>
                <div class="cpr-more"><?= h(__('and %s more', $narrowerCount - count($narrower['items']))) ?></div>
            <?php endif; ?>
        </div>
    <?php endif; ?>
</div>

<div>
    <?= $this->element('genericElementsBS5/Forms/section_label', [
        'accent' => $accent['key'],
        'label' => __('Still ongoing?'),
        'class' => 'mb-2',
    ]) ?>
    <div class="cpr-choices" role="radiogroup" aria-label="<?= h(__('Still ongoing?')) ?>">
        <label class="cpr-choice">
            <input class="form-check-input" type="radio" name="data[Collection][analysis]" value="1"<?= $analysis !== 2 ? ' checked' : '' ?>>
            <span>
                <span class="cpr-choice-title"><?= __('Ongoing') ?></span>
                <span class="cpr-choice-hint"><?= __('Partners see the investigation as still in progress.') ?></span>
            </span>
        </label>
        <label class="cpr-choice">
            <input class="form-check-input" type="radio" name="data[Collection][analysis]" value="2"<?= $analysis === 2 ? ' checked' : '' ?>>
            <span>
                <span class="cpr-choice-title"><?= __('Completed') ?></span>
                <span class="cpr-choice-hint"><?= __('Partners see it as finished.') ?></span>
            </span>
        </label>
    </div>
    <?= $this->element('genericElementsBS5/Forms/field_hint', [
        'text' => __('Publishing sends all of this to partners together; until then they keep the version they last received.'),
        'icon' => 'fas fa-share-nodes',
        'class' => 'mt-2',
    ]) ?>
</div>
<?php
$bodyHtml = ob_get_clean();

echo $this->element('genericElementsBS5/Modals/confirmation_form', [
    'model' => 'Collection',
    'url' => $baseurl . '/collections/publish/' . $collection['id'],
    'hiddenField' => false,
    'eyebrow' => __('Publication'),
    'accent' => $accent['key'],
    'title' => __('Review and publish'),
    'description' => $collection['name'],
    'message' => $withheld
        ? ($lastPublished
            ? __('Partners hold this collection as it was published %s. Share what changed since?', $ago($lastPublished))
            : __('Partners have not received this collection yet. Share it with them?'))
        : __('Partners already hold this collection as it is. Publish again to update how far the investigation went.'),
    'bodyHtml' => $bodyHtml,
    'submitLabel' => __('Publish'),
    'submitIcon' => 'upload',
    'icon' => 'fas fa-upload',
    'meta' => [['label' => __('Collection'), 'id' => $collection['id']]],
]);
