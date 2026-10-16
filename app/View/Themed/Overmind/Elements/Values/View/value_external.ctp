<?php
/**
 * Where this value appears outside this instance's own events.
 *
 * "Is anyone outside our instance seeing this?" — corroboration from
 * somewhere this instance does not control, which is why it sits apart
 * from the sightings card.
 *
 * **A count, and the count is the link.** The detail — which feed, which
 * sync server, and which remote event inside them — is the Relationships
 * tab's fourth section, reading the same filtered method this card
 * counts (`tabs/03-relationships.md` §20.1). A rail has room for a
 * number; naming five feeds and their events in it does not make the
 * number easier to read.
 *
 * Every number here is the sources this reader may see, like every other
 * number on the page. There is no count of what is withheld and no
 * standing caveat — `live/00-contract.md` §14.6 — but a reader whose
 * role reaches nothing is told so, keyed on the role and identical on
 * every value.
 *
 * Lazily loaded into `.ajax-card` from ValuesController::viewExternal.
 *
 * @var array $valueIntelligence
 * @var string $valueB64
 */
$external = $valueIntelligence['external'];
$counts = $external['counts'];
$restricted = $external['restricted'];
$cached = $external['cached'];

$hits = $counts['feeds'] + $counts['servers'];
$nothingCached = empty($cached['feeds']) && empty($cached['servers']);
/*
 * Role and instance config, never this value. A reader whose role
 * reaches no cached source searched nothing, so "not seen outside this
 * instance" would be a finding no lookup backs — and it would read the
 * same on every value they ever open. The section states this at
 * length; the card has room for the distinction and not the reason.
 */
$nothingVisible = empty($external['visible']['feeds'])
    && empty($external['visible']['servers']);
// keyed on the role, shown on every value — see the section's own note
$roleRestricted = $restricted['feeds'] || $restricted['servers'];

if ($hits) {
    $subtitle = h(__n('%d source holds it', '%d sources hold it',
        $hits, $hits));
} elseif ($nothingCached) {
    $subtitle = h(__('Nothing is cached to look in'));
} elseif ($nothingVisible) {
    $subtitle = h(__('Nothing your role can search'));
} else {
    $subtitle = h(__('Not seen outside this instance'));
}

/*
 * `$valueB64` rather than encoding the value again here: the controller's
 * own encoder is URL-safe, and a value carrying `/` would not survive a
 * plain base64 in a path segment.
 */
$sectionUrl = $this->Html->url(array(
    'controller' => 'values',
    'action' => 'view',
    $valueB64,
)) . '#tab-relationships';
?>
<div class="card shadow-sm mb-3 vp-panel"
     style="--vp-panel-color: var(--enrichment);">

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('External presence'),
        'panelIcon' => 'fas fa-cloud-arrow-down',
        'panelColor' => 'var(--enrichment)',
        'panelSub' => $subtitle,
    )) ?>

    <div class="p-3 d-flex flex-column gap-3">

        <?php if ($roleRestricted): ?>
            <div class="vp-acl-note-band">
                <i class="fas fa-lock"></i>
                <span>
                    <?php if ($restricted['feeds'] && $restricted['servers']): ?>
                        <?= __('Feeds an administrator has not published for lookup, and sync server hits, are shown to site admins only. Neither is counted here, on any value.') ?>
                    <?php elseif ($restricted['feeds']): ?>
                        <?= __('Feeds an administrator has not published for lookup are shown to site admins only, so they are not counted here, on any value.') ?>
                    <?php else: ?>
                        <?= __('Sync server hits require site admin, so they are not counted here, on any value.') ?>
                    <?php endif; ?>
                </span>
            </div>
        <?php endif; ?>

        <?php if ($nothingCached): ?>

            <div class="vp-empty">
                <i class="fas fa-cloud"></i>
                <span>
                    <?= __('No feed or sync server on this instance has caching enabled.') ?>
                </span>
            </div>

        <?php elseif ($nothingVisible): ?>

            <div class="vp-empty vp-empty-denied">
                <i class="fas fa-lock"></i>
                <span>
                    <?= __('Your role may be told about none of the cached sources, so nothing was looked up.') ?>
                </span>
            </div>

        <?php elseif (!$hits): ?>

            <div class="vp-empty vp-empty-novel">
                <i class="fas fa-fingerprint"></i>
                <span>
                    <?= __('No feed or sync server you can see holds this value.') ?>
                </span>
            </div>

        <?php else: ?>

            <?php
            /*
             * **A line counts sources; the clause after it counts the
             * remote events inside them.** Both numbers were here
             * before and only one was attached to anything: the card
             * drew *1 hit on sync servers* and, under both lines, *12
             * remote events name this value* — a total across feeds and
             * servers, sitting beneath two lines and belonging to
             * neither. On a value hitting one kind it read as that
             * kind's number and happened to be right; on a value
             * hitting both it read as one line's and was not.
             *
             * `event_counts` splits it. Each line now states the
             * sources it found and the remote events in them, and the
             * card has no figure a reader has to attribute.
             */
            $eventCounts = $external['event_counts'];
            $lines = array(
                array(
                    'icon' => 'fas fa-rss',
                    'count' => $counts['feeds'],
                    'label' => __n('%d feed holds it', '%d feeds hold it',
                        $counts['feeds']),
                    // caching is independent of enabling: a disabled feed
                    // can hold a populated cache, so "pulls from" would
                    // be wrong for most rows on a real instance
                    'sub' => __('Held in a feed cache on this instance'),
                    'events' => $eventCounts['feeds'],
                ),
                array(
                    'icon' => 'fas fa-server',
                    'count' => $counts['servers'],
                    'label' => __n('%d sync server holds it',
                        '%d sync servers hold it', $counts['servers']),
                    'sub' => __('Held in a connected server\'s cache'),
                    'events' => $eventCounts['servers'],
                ),
            );
            ?>
            <?php foreach ($lines as $line): ?>
                <?php if (!$line['count']) { continue; } ?>
                <a class="vp-external-row text-decoration-none text-reset"
                   href="<?= h($sectionUrl) ?>"
                   title="<?= h(__('Open the Relationships tab, where each source and its remote events are listed')) ?>">
                    <i class="<?= h($line['icon']) ?>"></i>
                    <div class="vp-min-w-0">
                        <div class="fw-semibold">
                            <?= h(sprintf($line['label'], $line['count'])) ?>
                        </div>
                        <div class="vp-fact-line-sub">
                            <?= h($line['sub']) ?>
                            <?php if (!empty($line['events'])): ?>
                                &nbsp;·&nbsp;<?= h(sprintf(
                                    __n(
                                        '%d remote event names it',
                                        '%d remote events name it',
                                        $line['events']
                                    ),
                                    $line['events']
                                )) ?>
                            <?php endif; ?>
                        </div>
                    </div>
                    <span class="vp-external-count">
                        <i class="fas fa-chevron-right"></i>
                    </span>
                </a>
            <?php endforeach; ?>

        <?php endif; ?>

        <div class="vp-panel-stub">
            <span class="vp-panel-stub-badge">
                <?= __('Not implemented') ?>
            </span>
            <div class="vp-panel-stub-note">
                <?= __('SightingDB is not read by this page. The primitive is Sightingdb::queryValues, and wiring it is a decision about querying a third party at render time.') ?>
            </div>
        </div>

    </div>

</div>
