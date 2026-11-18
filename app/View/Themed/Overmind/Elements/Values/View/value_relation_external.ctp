<?php
/**
 * The Relationships rail's Outside this instance: the cached feeds and sync
 * servers holding this exact value (set membership on a hash, never a
 * likeness), each with the remote events it names, which open a preview
 * from the source as it is now.
 *
 * Absence is a finding and is scoped to who asked: the sources this
 * reader's role searched, never the instance's total, and a reader whose
 * role reaches no source is told nothing was looked up. The role notice is
 * keyed on the reader, shown on every value alike.
 *
 * Lazily loaded from ValuesController::viewRelationExternal.
 *
 * @var array $valueIntelligence
 */
$external = $valueIntelligence['external'];
$sources = $external['sources'];
$counts = $external['counts'];
$restricted = $external['restricted'];
$cached = $external['cached'];
$visible = $external['visible'];
$eventFold = 3;

$nothingCached = empty($cached['feeds']) && empty($cached['servers']);
$nothingVisible = empty($visible['feeds']) && empty($visible['servers']);
$roleRestricted = $restricted['feeds'] || $restricted['servers'];

/**
 * "%d feeds and %d sync servers", dropping the kind that is zero.
 *
 * @param int $feeds
 * @param int $servers
 * @param bool $namesCache Whether the feed half names the cache
 * @return string
 */
$sourcePhrase = function ($feeds, $servers, $namesCache = false) {
    $parts = array();
    if ($feeds) {
        $parts[] = sprintf($namesCache
            ? __n('%d cached feed', '%d cached feeds', $feeds)
            : __n('%d feed', '%d feeds', $feeds), $feeds);
    }
    if ($servers) {
        $parts[] = sprintf(__n('%d sync server', '%d sync servers', $servers), $servers);
    }
    if (count($parts) === 2) {
        return sprintf(__('%1$s and %2$s'), $parts[0], $parts[1]);
    }
    return empty($parts) ? '' : $parts[0];
};
$searched = $sourcePhrase($visible['feeds'], $visible['servers'], true);

$searchedCount = (int)$visible['feeds'] + (int)$visible['servers'];
if (!empty($sources)) {
    $sub = h(sprintf(
        __n('In %1$s of the %2$s source searched', 'In %1$s of the %2$s sources searched', $searchedCount),
        number_format(count($sources)),
        number_format($searchedCount)
    ));
    if (!empty($external['events'])) {
        $sub .= ' · ' . h(sprintf(__n('%s remote event', '%s remote events', $external['events']),
            number_format($external['events'])));
    }
} elseif ($nothingCached || $nothingVisible) {
    $sub = h(__('Nothing looked up'));
} else {
    $sub = h(__('Not seen outside this instance'));
}
?>
<div class="card shadow-sm mb-3 vp-panel vp-rel-k-external"
     style="--vp-panel-color: var(--vp-rel-external);"
     id="vp-external-presence"
     data-vp-rel-summary="external"
     data-vp-rel-count="<?= h(number_format(count($sources))) ?>"
     <?= $roleRestricted ? 'data-vp-rel-note="' . h(__('some sources withheld')) . '"' : '' ?>>

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('Outside this instance'),
        'panelIcon' => 'fas fa-cloud-arrow-down',
        'panelColor' => 'var(--vp-rel-external)',
        'panelSub' => $sub,
    )) ?>

    <?php if ($nothingCached): ?>
        <div class="vp-rail-none">
            <?= __('No feed or sync server on this instance has caching enabled, so there is nothing to look this value up in.') ?>
        </div>
    <?php elseif ($nothingVisible): ?>
        <div class="vp-rail-none">
            <?= h(sprintf(
                __('This instance caches %s and your role may be told about none of them, so nothing was looked up. That does not say the value is absent from them.'),
                $sourcePhrase($cached['feeds'], $cached['servers'])
            )) ?>
        </div>
    <?php elseif (empty($sources)): ?>
        <div class="vp-ext-novel">
            <i class="fas fa-fingerprint" aria-hidden="true"></i>
            <span>
                <strong><?= h(sprintf(
                    $roleRestricted ? __('In none of the %s your role can read.') : __('In none of the %s this instance holds.'),
                    $searched
                )) ?></strong>
                <?= h($roleRestricted
                    ? __('Locally unique, as far as your role can see.')
                    : __('Locally unique, as far as this instance can see.')) ?>
            </span>
        </div>
    <?php else: ?>
        <ul class="vp-ext-list">
            <?php foreach ($sources as $source): ?>
                <?php $isServer = $source['scope'] === 'server'; ?>
                <li class="vp-ext-src">
                    <div class="vp-ext-head">
                        <span class="vp-ext-ic" aria-hidden="true"><i class="fas <?= $isServer ? 'fa-server' : 'fa-rss' ?>"></i></span>
                        <span class="vp-ext-name">
                            <a href="<?= h($baseurl . ($isServer ? '/servers/view/' : '/feeds/view/') . (int)$source['id']) ?>"
                               title="<?= h((string)$source['url']) ?>"><?= h($source['name']) ?></a>
                            <span class="vp-ext-kind"><?= h($isServer
                                ? __('sync server')
                                : trim($source['kind'] . (empty($source['provider']) ? '' : ' · ' . $source['provider']))) ?></span>
                        </span>
                        <?php if (!empty($source['events_total'])): ?>
                            <span class="vp-ext-n" title="<?= h(__('Remote events naming this value')) ?>"><?=
                                h(number_format($source['events_total'])) ?></span>
                        <?php endif; ?>
                    </div>
                    <?php if (empty($source['events'])): ?>
                        <div class="vp-ext-events vp-ext-empty"><?= __('Holds the value; publishes no event to open.') ?></div>
                    <?php else: ?>
                        <div class="vp-ext-events">
                            <?php foreach ($source['events'] as $at => $event): ?>
                                <a class="vp-ext-event<?= $at >= $eventFold ? ' d-none' : '' ?>" href="<?= h($event['url']) ?>"
                                   <?= $at >= $eventFold ? 'data-vp-ext-fold' : '' ?>
                                   title="<?= h(sprintf(__('Preview this event from %s, as it is now'), $source['name'])) ?>">
                                    <i class="fas fa-arrow-up-right-from-square" aria-hidden="true"></i><span><?= h($event['name']) ?></span>
                                </a>
                            <?php endforeach; ?>
                            <?php $more = $source['events_total'] - min($eventFold, count($source['events'])); ?>
                            <?php if ($more > 0): ?>
                                <button type="button" class="vp-ext-more" data-vp-ext-more
                                        <?= count($source['events']) <= $eventFold ? 'disabled' : '' ?>
                                        title="<?= h(count($source['events']) < $source['events_total']
                                            ? sprintf(__('%1$s of %2$s are listed here'), count($source['events']), $source['events_total'])
                                            : __('Show them')) ?>"><?= h(sprintf(__('+%s more'), number_format($more))) ?></button>
                            <?php endif; ?>
                        </div>
                    <?php endif; ?>
                </li>
            <?php endforeach; ?>
        </ul>
    <?php endif; ?>

    <?php if ($roleRestricted && !$nothingCached): ?>
        <div class="vp-rail-foot">
            <i class="fas fa-lock" aria-hidden="true"></i>
            <?php if ($restricted['feeds'] && $restricted['servers']): ?>
                <?= __('Feeds not published for lookup, and sync server hits, are shown to site admins only, on every value.') ?>
            <?php elseif ($restricted['feeds']): ?>
                <?= __('Feeds not published for lookup are shown to site admins only, on every value.') ?>
            <?php else: ?>
                <?= __('Sync server hits are shown to site admins only, on every value.') ?>
            <?php endif; ?>
        </div>
    <?php endif; ?>
</div>
