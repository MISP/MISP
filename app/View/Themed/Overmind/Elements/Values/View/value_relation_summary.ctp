<?php
/**
 * The tab's contents page: one card per section, each carrying that
 * section's headline number and jumping to it.
 *
 * The tab is seven tables tall and every one of them is worth reading,
 * which is exactly the problem — a reader who wants to know whether
 * anybody asserted anything about this value has to scroll past a
 * hundred co-occurring values to find out. The strip answers that
 * before the scroll: seven numbers in one glance, and a press to land
 * on the one that is not zero.
 *
 * **It holds no data and costs nothing.** Every number here is filled
 * in by the panel that owns it, as that panel lands — the panels are
 * lazily loaded precisely because some of them are expensive, and a
 * strip that computed its own totals would run the 20,000-row scan
 * over again to print one integer. Until a panel arrives its card
 * shows a placeholder rather than a zero, because *not yet read* and
 * *nothing there* are different answers and this tab's whole
 * discipline is not conflating them.
 *
 * **Seven cards over six endpoints.** The co-occurrence endpoint draws
 * two sections — what sits in the same object, and what sits in the
 * same events — so two cards point into the same container, and the
 * first of them is dropped when that panel renders no sibling table.
 * `initRelationSummary` in `value-intelligence.js` does both.
 *
 * **The units differ and each card says which.** Values, siblings,
 * relations, matches, remote events, references, claims — seven
 * notions and seven units, so nothing here is a total and nothing
 * invites being summed. Same rule the "What is counted" card in the
 * rail states at length.
 *
 * @var array $data
 */

/*
 * In page order, top to bottom, so the strip reads as the contents it
 * is. `anchor` is the lazily-loaded container the card jumps to;
 * `key` is what the panel inside it stamps on itself.
 */
$sections = array(
    array(
        'key' => 'siblings',
        'anchor' => 'vp-rel-sec-cooccurrence',
        'title' => __('In the same object'),
        'unit' => __('siblings'),
        'icon' => 'misp-icon misp-icon-object misp-simple',
        'colour' => 'var(--vp-rel-co)',
    ),
    array(
        'key' => 'cooccurrence',
        'anchor' => 'vp-rel-sec-cooccurrence',
        'title' => __('In the same events'),
        'unit' => __('values'),
        'icon' => 'fas fa-link',
        'colour' => 'var(--vp-rel-co)',
    ),
    /*
     * §10.2. Its own card because it is its own section, and directly
     * under the co-occurrence one because it shares that panel and that
     * anchor — the labels are read from the same scan over the same
     * events, and listed beneath the values they surround.
     *
     * `clusters and tags` rather than a word covering both: there is no
     * such word in MISP that a reader would recognise, and *labels* is
     * this brief's coinage rather than the product's.
     */
    array(
        'key' => 'labels',
        'anchor' => 'vp-rel-sec-cooccurrence',
        'title' => __('Labels in this neighbourhood'),
        'unit' => __('clusters and tags'),
        'icon' => 'misp-icon misp-icon-galaxy misp-simple',
        'colour' => 'var(--vp-rel-co)',
    ),
    array(
        'key' => 'dated',
        'anchor' => 'vp-rel-sec-dated',
        'title' => __('Dated relations'),
        'unit' => __('relations'),
        'icon' => 'fas fa-clock-rotate-left',
        'colour' => 'var(--vp-rel-object)',
    ),
    array(
        'key' => 'near',
        'anchor' => 'vp-rel-sec-near',
        'title' => __('Near-matches'),
        'unit' => __('matches'),
        'icon' => 'fas fa-code-compare',
        'colour' => 'var(--vp-rel-near)',
    ),
    array(
        'key' => 'external',
        'anchor' => 'vp-rel-sec-external',
        'title' => __('Outside this instance'),
        'unit' => __('remote events'),
        'icon' => 'fas fa-cloud-arrow-down',
        'colour' => 'var(--vp-rel-external)',
    ),
    array(
        'key' => 'references',
        'anchor' => 'vp-rel-sec-references',
        'title' => __('Object relationships'),
        'unit' => __('references'),
        'icon' => 'fas fa-diagram-project',
        'colour' => 'var(--vp-rel-reference)',
    ),
    array(
        'key' => 'asserted',
        'anchor' => 'vp-rel-sec-asserted',
        'title' => __('Asserted by analysts'),
        'unit' => __('claims'),
        'icon' => 'misp-icon misp-icon-analyst-note misp-simple',
        'colour' => 'var(--vp-rel-human)',
    ),
);
?>
<nav class="vp-relsum"
     data-vp-relsum-strip
     aria-label="<?= h(__('Sections on this tab')) ?>">
    <?php foreach ($sections as $section): ?>
        <?php
        /*
         * An anchor and not a button: it has a real destination, so
         * middle-click and "open in new tab" mean something, and it
         * keeps working if the script never runs. The script takes the
         * press over only to scroll smoothly and to leave the address
         * bar alone — the hash on this page routes tabs, and a section
         * id in it would send a reload to the wrong tab.
         */
        ?>
        <a class="vp-relsum-card vp-relsum-pending"
           href="#<?= h($section['anchor']) ?>"
           data-vp-relsum="<?= h($section['key']) ?>"
           style="--vp-panel-color: <?= h($section['colour']) ?>;">
            <span class="vp-relsum-head">
                <?php if (strpos($section['icon'], 'misp-icon') === 0): ?>
                    <span class="<?= h($section['icon']) ?>"></span>
                <?php else: ?>
                    <i class="<?= h($section['icon']) ?>"></i>
                <?php endif; ?>
                <span class="vp-relsum-title"><?= h($section['title']) ?></span>
            </span>
            <span class="vp-relsum-figure">
                <?php
                /*
                 * No `aria-live`. Seven of them announce seven numbers
                 * in the second the panels land, over each other and
                 * over whatever the reader was on; the figure is in the
                 * link's own text and is read when the link is reached,
                 * which is when it is wanted.
                 */
                ?>
                <span class="vp-relsum-n" data-vp-relsum-count>…</span>
                <span class="vp-relsum-unit"><?= h($section['unit']) ?></span>
            </span>
            <span class="vp-relsum-note" data-vp-relsum-note hidden></span>
        </a>
    <?php endforeach; ?>
</nav>
