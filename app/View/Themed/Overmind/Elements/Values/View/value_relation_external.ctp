<?php
/**
 * Section four: where this value sits in somebody else's events.
 *
 * The fourth notion of "related" on this tab, and the only one whose
 * rows are not on this instance. A MISP-format feed or a cached sync
 * server holds the value inside a remote event, and that event can be
 * named and opened — co-occurrence outside the instance boundary, which
 * nothing else on this page can see past.
 *
 * Three things this section is careful about:
 *
 *   the count matches   a source that holds the value but publishes no
 *                       event still gets a row, marked as such. Drop
 *                       those and the Overview card's number stops
 *                       matching the rows here, which makes a reader
 *                       distrust both.
 *   the notice is role  "your role cannot see this" is keyed on the
 *                       reader and shown on every value alike, never on
 *                       whether this value hit something withheld. A
 *                       notice that appeared only when something was
 *                       hidden would be an existence oracle at one bit
 *                       (`live/00-contract.md` §14.6).
 *   the link leaves     opening a remote event previews it from the
 *                       feed or server at request time. It is the only
 *                       affordance on this page that is not a local
 *                       read, so it says so — and it says *preview*
 *                       rather than *fetch*, because a MISP reader hears
 *                       "fetch" as pulling the event into this instance,
 *                       which is precisely what previewEvent does not
 *                       do.
 *
 * **Counts lead and the UUIDs fold** (subphase B3). A row's headline is
 * how much presence the source holds; the event pills are a wall of
 * UUIDs, which is a click target rather than information, so they sit
 * behind the row's own expander. `<details>` rather than the ledger's
 * Bootstrap collapse because this fragment is injected lazily and binds
 * no JS of its own — a fold that needs `misp:container-loaded` to have
 * fired is a fold that can arrive inert.
 *
 * **Absence is the finding, and it is scoped to who asked.** A value in
 * no cached source is locally novel, which is among the strongest triage
 * facts this page can state — so the miss state states it, with the
 * denominator attached. The denominator is the sources *this reader's
 * role searched*, never the instance's total: "0 of 5" when four of the
 * five were never looked in reads as coverage the reader did not get.
 * And a reader whose role reaches no source at all is told that nothing
 * was looked up, rather than being handed a novelty claim no search
 * backs — the same sentence would be false for them on every value.
 *
 * The Overview's `value_external` card counts what this section lists,
 * through one `forExternal` (`tabs/03-relationships.md` §20.1), and its
 * miss state reads *"Not seen outside this instance"*. This section's
 * novelty sentence is that sentence with the denominator attached; if
 * the wording moves it moves in both.
 *
 * Lazily loaded from ValuesController::viewRelationExternal.
 *
 * @var array $valueIntelligence
 * @var string $valueB64
 */
$external = $valueIntelligence['external'];
$sources = $external['sources'];
$counts = $external['counts'];
$restricted = $external['restricted'];
$cached = $external['cached'];
$visible = $external['visible'];

$nothingCached = empty($cached['feeds']) && empty($cached['servers']);
/*
 * Role and instance config, never this value: true whenever the reader
 * may be told about no cached source at all, whether or not this
 * particular value would have hit one.
 */
$nothingVisible = empty($visible['feeds']) && empty($visible['servers']);
/*
 * Shown whenever this reader's role cannot reach a kind of source the
 * instance holds — on every value alike, and whether or not this one hit
 * anything. Gating it on "something was withheld for this value" would
 * make its presence the disclosure §14.6 forbids; gating it on "no hits
 * at all" would leave a reader who can see feeds never told that servers
 * are withheld from them.
 */
$roleRestricted = $restricted['feeds'] || $restricted['servers'];

/**
 * "%d feeds and %d sync servers", dropping the kind that is zero.
 *
 * Three callers with three meanings — how many sources *hold* the value,
 * how many this role *searched*, and how many the instance *caches* — so
 * the phrase is built once and the caller supplies the pair. The two
 * denominators say "cached" because a denominator has to name the
 * population it counts; the numerator does not, and would read as a
 * claim about caching rather than about this value.
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
        $parts[] = sprintf(
            __n('%d sync server', '%d sync servers', $servers), $servers);
    }
    if (count($parts) === 2) {
        return sprintf(__('%1$s and %2$s'), $parts[0], $parts[1]);
    }
    return empty($parts) ? '' : $parts[0];
};

$holding = $sourcePhrase($counts['feeds'], $counts['servers']);
$searched = $sourcePhrase($visible['feeds'], $visible['servers'], true);
// plain noun: the sentence it lands in already says "caches"
$instanceHolds = $sourcePhrase($cached['feeds'], $cached['servers']);

$icon = 'fas fa-cloud-arrow-down';
?>
<div class="card shadow-sm mb-3 vp-panel vp-rel-k-external"
     style="--vp-panel-color: var(--vp-rel-external);"
     id="vp-external-presence"
     data-vp-list
     data-vp-rel-summary="external"
     data-vp-rel-count="<?= h(number_format($external['events'])) ?>"
     <?php if ($roleRestricted): ?>
         data-vp-rel-note="<?= h(__('some sources withheld')) ?>"
     <?php endif; ?>>

    <?php
    ob_start();
    ?>
        <span class="vp-rel-tag me-1">
            <i class="<?= h($icon) ?>"></i><?= h(__('Outside this instance')) ?>
        </span>
        <?php if (!empty($sources)): ?>
            <?= h($holding) ?>
            <?php if (!empty($external['events'])): ?>
                &nbsp;·&nbsp;<?= h(sprintf(
                    __n('%d remote event', '%d remote events',
                        $external['events']),
                    $external['events']
                )) ?>
            <?php endif; ?>
            &nbsp;·&nbsp;
        <?php endif; ?>
        <span class="vp-rel-prov"><i class="fas fa-gauge"></i><?=
            h(__('Machine-derived')) ?></span>
        &nbsp;·&nbsp;<?= h(__('feed cache')) ?>
    <?php
    $headerSub = ob_get_clean();
    ?>

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('Outside this instance'),
        'panelIcon' => $icon,
        'panelColor' => 'var(--vp-rel-external)',
        'panelSub' => $headerSub,
    )) ?>

    <div class="vp-rel-cap">
        <i class="fas fa-circle-info"
           title="<?= h(__(
               'Set membership on a hash — no CIDR, no substring'
               . ' and no near-match — so it is never a statement'
               . ' that two values are alike.'
           )) ?>"></i>
        <span>
            <?= __('A hit means a feed or sync server cache holds'
                . ' this exact value.') ?>
        </span>
    </div>

    <div class="p-3">

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
                    <?= __('No feed or sync server on this instance has caching enabled, so there is nothing to look this value up in.') ?>
                </span>
            </div>

        <?php elseif ($nothingVisible): ?>

            <?php
            /*
             * Nothing was searched, so nothing may be concluded. The
             * novelty sentence below would be false for this reader on
             * every value alike, which is exactly the shape of claim
             * this page refuses to make.
             */
            ?>
            <div class="vp-empty vp-empty-denied">
                <i class="fas fa-lock"></i>
                <span>
                    <?= h(sprintf(
                        __('This instance caches %s, and your role may be'
                            . ' told about none of them, so nothing was'
                            . ' looked up. This is not a statement that'
                            . ' the value is absent from them.'),
                        $instanceHolds
                    )) ?>
                </span>
            </div>

        <?php elseif (empty($sources)): ?>

            <div class="vp-empty vp-empty-novel">
                <i class="fas fa-fingerprint"></i>
                <span>
                    <?php if ($roleRestricted): ?>
                        <strong><?= h(sprintf(
                            __('In 0 of %s your role can read.'),
                            $searched
                        )) ?></strong>
                        <?= __('Locally unique, as far as your role can see.') ?>
                    <?php else: ?>
                        <strong><?= h(sprintf(
                            __('In 0 of %s this instance holds.'),
                            $searched
                        )) ?></strong>
                        <?= __('Locally unique, as far as this instance can see.') ?>
                    <?php endif; ?>
                </span>
            </div>

        <?php else: ?>

            <div class="table-responsive" data-vp-list-rows>
                <table class="table table-sm table-hover vp-table
                              align-middle mb-0">
                    <thead>
                        <tr>
                            <th scope="col"><?= __('Source') ?></th>
                            <th scope="col"><?= __('Kind') ?></th>
                            <th scope="col"><?= __('Remote events') ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($sources as $source): ?>
                            <tr class="vp-rel-stripe vp-rel-k-external">
                                <td>
                                    <div class="vp-rel-cell fw-semibold"
                                         title="<?= h($source['name']) ?>">
                                        <?= h($source['name']) ?>
                                    </div>
                                    <?php if (!empty($source['url'])): ?>
                                        <div class="vp-fact-line-sub vp-rel-cell"
                                             title="<?= h($source['url']) ?>">
                                            <?= h($source['url']) ?>
                                        </div>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <span class="vp-rel-tag">
                                        <i class="fas <?= $source['scope'] === 'server'
                                            ? 'fa-server' : 'fa-rss' ?>"></i><?=
                                            h($source['kind']) ?>
                                    </span>
                                </td>
                                <td>
                                    <?php if (empty($source['events'])): ?>
                                        <span class="vp-empty-inline">
                                            <?= __('Holds the value; publishes no event to open') ?>
                                        </span>
                                    <?php else: ?>
                                        <details class="vp-external-fold">
                                            <summary title="<?= h(sprintf(
                                                __('Show the remote events %s names this value in'),
                                                $source['name']
                                            )) ?>">
                                                <span class="vp-external-hits"><?=
                                                    h(number_format($source['events_total'])) ?></span>
                                                <span class="vp-external-hits-unit"><?=
                                                    h(__n('remote event', 'remote events',
                                                        $source['events_total'])) ?></span>
                                                <i class="fas fa-chevron-down"></i>
                                            </summary>
                                            <?php
                                            /*
                                             * Not `.d-flex`. Bootstrap
                                             * declares it `!important`,
                                             * which beats the closed
                                             * `<details>` and leaves the
                                             * pills on screen with the
                                             * fold shut — caught in the
                                             * browser, invisible in the
                                             * markup.
                                             */
                                            ?>
                                            <div class="vp-external-pills">
                                                <?php foreach ($source['events'] as $event): ?>
                                                    <a class="vp-external-event"
                                                       href="<?= h($event['url']) ?>"
                                                       title="<?= h(sprintf(
                                                           __('Preview this event from %s'),
                                                           $source['name']
                                                       )) ?>">
                                                        <i class="fas fa-arrow-up-right-from-square"></i>
                                                        <?= h($event['name']) ?>
                                                    </a>
                                                <?php endforeach; ?>
                                            </div>
                                            <?php if ($source['events_total'] > count($source['events'])): ?>
                                                <div class="vp-fact-line-sub mt-1">
                                                    <?= h(sprintf(
                                                        __('Showing %1$s of %2$s.'),
                                                        count($source['events']),
                                                        $source['events_total']
                                                    )) ?>
                                                </div>
                                            <?php endif; ?>
                                        </details>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

            <div class="vp-fact-line-sub mt-2">
                <i class="fas fa-arrow-up-right-from-square"></i>
                <?= __('Opening a remote event previews it from the feed or server as it is right now. Every other link on this page reads local data.') ?>
            </div>

        <?php endif; ?>

    </div>

</div>
