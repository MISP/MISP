<?php
/**
 * What the community has labelled this value.
 *
 * Tags are grouped by taxonomy rather than listed flat, because a
 * taxonomy is the unit that can disagree with itself: two events putting
 * `tlp:amber` and `tlp:green` on the same value is a fact about the
 * value, and a flat list hides it. Where a taxonomy is ordinal —
 * `admiralty-scale` and its kin — the group renders as a position on a
 * scale instead of a string nobody reads.
 *
 * **One list over both scopes.** A label reaches this card from the
 * value's occurrences or from the events those occurrences sit in, and
 * the two are drawn together: an attribute is covered by its event's
 * labelling, so *tagged on the report* and *tagged on the indicator*
 * are one statement about the value made at two removes. They were two
 * sections with a glyph telling them apart for one day; what that
 * bought was a heading and half the card's height separating a long
 * list from a usually empty one, since most attributes carry no tag of
 * their own.
 *
 * **No `×N` beside a chip, and that is the fold's price.** The
 * occurrence scope counts occurrences and the event scope counts
 * events; their union is a third number neither read holds and buying
 * it costs a second pass over the value's `attribute_tags`. So each
 * chip's title states whichever counts it has, under their own names,
 * and the page keeps its rule that every `×N` on it counts one thing.
 * `ValueIntelligence::mergeTagScopes` carries both.
 *
 * **Clusters are grouped under their galaxy**, which is the thing they
 * are members of. Flat, the card put a tool, a threat actor and four
 * ATT&CK techniques in one run with each chip repeating its own kind in
 * small print; the galaxy is what they have in common, so it heads them
 * and is said once.
 *
 * Lazily loaded into `.ajax-tab-content` from
 * ValuesController::viewContext.
 *
 * @var array $valueIntelligence
 * @var string $valueB64
 */
$profile = $valueIntelligence;
$taxonomies = $profile['tags'];
$galaxies = $profile['galaxies'];
$tagCap = isset($profile['tag_cap']) ? $profile['tag_cap'] : null;

/*
 * **The dimensions the reader always wants, and this value has none
 * of** (`02-context-priority.md` §4). Only a pinned taxonomy or galaxy
 * is drawn absent, because an unlabelled value is not an unrestricted
 * one and a reader who does not notice the label is missing will
 * assume they saw it. It says nothing about what they cannot see: no
 * tag of this dimension is on this value *within what this reader may
 * read*, which is the page's standing rule, and there is no count of
 * anything withheld.
 */
$absent = array();
if (!empty($profile['absent'])) {
    foreach (array('taxonomies', 'galaxies') as $kind) {
        foreach ($profile['absent'][$kind] as $row) {
            $absent[] = array('key' => $row['key'], 'kind' => $kind);
        }
    }
}

/*
 * **A pinned handling label renders the most restrictive one, and
 * counts the rest** (§4). A value's context tags come from every
 * occurrence's event as well as from the attributes, so a shared value
 * almost always carries more than one `tlp` — and a reader who sees
 * `tlp:clear` in the pinned slot and misses `tlp:red` two chips away
 * has been misled in exactly the way the tier exists to prevent. The
 * others are named in the count's title rather than dropped.
 */
foreach ($taxonomies as $at => $taxonomy) {
    if (empty($taxonomy['lead'])) {
        continue;
    }
    $others = array();
    foreach ($taxonomy['tags'] as $tag) {
        if ($tag['name'] !== $taxonomy['lead']['tag']['name']) {
            $others[] = $tag['name'];
        }
    }
    $taxonomies[$at]['tags'] = array($taxonomy['lead']['tag']);
    $taxonomies[$at]['lead_more'] = $taxonomy['lead']['others'];
    $taxonomies[$at]['lead_others'] = $others;
}

$conflicts = 0;
foreach ($taxonomies as $taxonomy) {
    if (!empty($taxonomy['conflict'])) {
        $conflicts++;
    }
}

$clusterCount = 0;
foreach ($galaxies as $galaxy) {
    $clusterCount += count($galaxy['clusters']);
}

/**
 * A row per taxonomy, or the taxonomies flowed into one band.
 *
 * **A height budget, and the number is measured.** A taxonomy row costs
 * 49px whether it holds one chip or ten, and folding the events' labels
 * in takes `8.8.8.8` from three taxonomies to ten — six of them a
 * single chip. A row each was 518px of a card the Overview holds at
 * 534, nearly all of it the white space to the right of a one-chip
 * group in a 1,000px card.
 *
 * Flowed, the same ten groups are 170px and **keep their names**: each
 * is its taxonomy's label and then its chips, wrapping as one unit, so
 * what is given up is the column alignment rather than the grouping.
 * What a row does buy is the ordinal scale, which needs the width — so
 * five, the point at which a value's taxonomies stop fitting as rows,
 * and below it the card draws exactly what it drew before it had two
 * scopes to fold.
 *
 * No scale is drawn in the flowed band, and on a value this broadly
 * labelled there would be none to draw in any case: a position means
 * *one tag of this dimension*, and `8.8.8.8` carries `tlp:white`,
 * `tlp:amber` and `tlp:red` from three different reports.
 */
const TAXONOMY_ROW_BUDGET = 5;
$flat = count($taxonomies) > TAXONOMY_ROW_BUDGET;
/*
 * Galaxies pay the same rent and are charged it the same way. `443` is
 * attributed to **nine** of them, which as a row each was 550px — more
 * than the whole card was before — against the two flat rows the
 * clusters occupied when they were only the occurrences'.
 */
$flatGalaxies = count($galaxies) > TAXONOMY_ROW_BUDGET;

/**
 * How many clusters of one galaxy the card draws before it says how
 * many more there are.
 *
 * ATT&CK is why: `8.8.8.8`'s events attribute it to twenty techniques,
 * which is 237px of one galaxy — more than the card's whole tag
 * section. Six is two lines of it, and the group still says what it
 * belongs to and how much of it was left out.
 */
const CLUSTERS_PER_GALAXY = 6;


/**
 * What a chip's two counts say, in the units they were read in.
 *
 * Both, one or neither: a label on the events alone — which is most of
 * them — says so rather than reading as a count of nothing.
 *
 * @param int|null $occurrences
 * @param int|null $events
 * @return string
 */
$reach = function ($occurrences, $events) {
    $onEvents = $events === null ? null : sprintf(
        __n(
            'On %s event this value appears in',
            'On %s events this value appears in',
            $events
        ),
        number_format($events)
    );
    if ($occurrences === null) {
        return $onEvents === null ? '' : $onEvents;
    }
    if ($onEvents === null) {
        return sprintf(
            __n(
                'On %s occurrence of this value',
                'On %s occurrences of this value',
                $occurrences
            ),
            number_format($occurrences)
        );
    }
    return $onEvents . sprintf(
        __n(
            ', and on %s occurrence of it directly',
            ', and on %s occurrences of it directly',
            $occurrences
        ),
        number_format($occurrences)
    );
};

$subtitle = implode(' &nbsp;·&nbsp; ', array(
    h(sprintf(
        __n('%s taxonomy', '%s taxonomies', count($taxonomies)),
        count($taxonomies)
    )),
    h(sprintf(
        __n('%s galaxy cluster', '%s galaxy clusters', $clusterCount),
        $clusterCount
    )),
));

$headerExtra = null;
if ($conflicts > 0) {
    $headerExtra = '<span class="vp-conflict" title="'
        . h(__(
            'Tags from the same taxonomy contradict each other here.'
            . ' Shown as they are, not resolved to one.'
        ))
        . '"><i class="fas fa-code-branch"></i>'
        . h(sprintf(__('%s in conflict'), $conflicts))
        . '</span>';
}
?>
<div class="card shadow-sm mb-3 vp-panel"
     style="--vp-panel-color: var(--tag);">

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('Tags and galaxies'),
        'panelIcon' => 'misp-icon misp-icon-tag misp-simple',
        'panelColor' => 'var(--tag)',
        'panelSub' => $subtitle,
        'panelExtra' => $headerExtra,
    )) ?>

    <?php if (empty($taxonomies) && empty($galaxies) && empty($absent)): ?>
        <div class="vp-empty">
            <i class="fas fa-tag"></i>
            <span><?= __('Nobody has tagged this value.') ?></span>
        </div>
    <?php else: ?>

        <?php if (empty($taxonomies) && empty($galaxies)): ?>
            <?php
            /*
             * Pinned and nothing else: the value is untagged, and the
             * absences below are the whole of what the card has to
             * say. Both statements are drawn, because *nobody tagged
             * this* and *this dimension is not recorded* answer
             * different questions.
             */
            ?>
            <div class="vp-empty">
                <i class="fas fa-tag"></i>
                <span><?= __('Nobody has tagged this value.') ?></span>
            </div>
        <?php endif; ?>

        <?php if (!empty($absent)): ?>
            <div class="vp-tax vp-tax-absent">
                <div class="vp-tax-name"><?= __('Always shown') ?></div>
                <div class="vp-tax-body">
                    <div class="vp-tax-tags">
                        <?php foreach ($absent as $row): ?>
                            <span class="vp-absent"
                                  title="<?= h($row['kind'] === 'galaxies'
                                      ? __('You always see this galaxy.'
                                          . ' Nothing on this value is'
                                          . ' attributed to one of its'
                                          . ' clusters.')
                                      : __('You always see this'
                                          . ' taxonomy. Nothing on this'
                                          . ' value carries a label'
                                          . ' from it.')) ?>">
                                <span class="vp-absent-name">
                                    <?= h($row['key']) ?>
                                </span>
                                <span class="vp-absent-note">
                                    <?= __('not recorded') ?>
                                </span>
                            </span>
                        <?php endforeach; ?>
                    </div>
                </div>
            </div>
        <?php endif; ?>

        <?php if ($tagCap !== null): ?>
            <?php
            /*
             * A cap is not a permission (§14.6), so it is stated on the
             * panel rather than left to be inferred from a list that
             * stops. It also explains the scales' absence: none is
             * drawn on a capped read, because a position means *one tag
             * of this dimension* and a truncated list cannot tell that
             * from *one that was read*.
             */
            ?>
            <div class="vp-filter-note">
                <i class="fas fa-filter"></i>
                <span><?= h(sprintf(
                    __('The %s most-carried labels. This value has more,'
                        . ' so no taxonomy is drawn as a scale here.'),
                    number_format($tagCap)
                )) ?></span>
            </div>
        <?php endif; ?>

        <?php if ($flat): ?>
            <div class="vp-tax vp-tax-flat">
                <div class="vp-tax-body">
                    <div class="vp-tax-tags">
                        <?php foreach ($taxonomies as $taxonomy): ?>
                            <span class="vp-tax-group">
                                <span class="vp-tax-group-name">
                                    <?= h($taxonomy['taxonomy']) ?>
                                    <?php if (!empty(
                                        $taxonomy['conflict']
                                    )): ?>
                                        <span class="vp-conflict-dot"
                                              title="<?= h(sprintf(
                                                  __('What has been'
                                                      . ' said about'
                                                      . ' this value'
                                                      . ' disagrees'
                                                      . ' about %s'),
                                                  $taxonomy['taxonomy']
                                              )) ?>"></span>
                                    <?php endif; ?>
                                </span>
                                <?php foreach (
                                    $taxonomy['tags'] as $tag
                                ): ?>
                                    <span class="vp-tag"
                                          title="<?= h($reach(
                                              $tag['occurrences'],
                                              $tag['events']
                                          )) ?>">
                                        <?= $this->element(
                                            'genericElementsBS5/Badges/tag',
                                            array(
                                                'tag' => $tag,
                                                'local' => !empty(
                                                    $tag['local']
                                                ),
                                                'hiddenClass' => '',
                                            )
                                        ) ?>
                                    </span>
                                <?php endforeach; ?>
                                <?php if (!empty(
                                    $taxonomy['lead_more']
                                )): ?>
                                    <span class="vp-tag-more"
                                          title="<?= h(implode(
                                              ', ',
                                              $taxonomy['lead_others']
                                          )) ?>"><?= h(sprintf(
                                        __n(
                                            'and %s other label',
                                            'and %s other labels',
                                            $taxonomy['lead_more']
                                        ),
                                        number_format(
                                            $taxonomy['lead_more']
                                        )
                                    )) ?></span>
                                <?php endif; ?>
                            </span>
                        <?php endforeach; ?>
                    </div>
                </div>
            </div>
        <?php endif; ?>

        <?php foreach ($flat ? array() : $taxonomies as $taxonomy): ?>
            <div class="vp-tax">
                <div class="vp-tax-name">
                    <?= h($taxonomy['taxonomy']) ?>
                    <?php if (!empty($taxonomy['conflict'])): ?>
                        <span class="vp-conflict-dot"
                              title="<?= h(__(
                                  'What has been said about this value'
                                  . ' disagrees'
                              )) ?>"></span>
                    <?php endif; ?>
                </div>
                <div class="vp-tax-body">

                    <?php if (!empty($taxonomy['scale'])):
                        $scale = $taxonomy['scale']; ?>
                        <div class="vp-scale">
                            <div class="vp-scale-track">
                                <?php for ($i = 1;
                                    $i <= $scale['of'];
                                    $i++
                                ): ?>
                                    <span class="vp-scale-seg<?=
                                        $i <= $scale['position']
                                            ? ' vp-scale-seg-on'
                                            : '' ?>"></span>
                                <?php endfor; ?>
                            </div>
                            <div class="vp-scale-reading">
                                <span class="fw-semibold">
                                    <?= h($scale['reading']) ?>
                                </span>
                                <span class="text-muted">
                                    <?= h($scale['label']) ?>
                                    <?= h(sprintf(
                                        __('(%1$s of %2$s)'),
                                        $scale['position'],
                                        $scale['of']
                                    )) ?>
                                </span>
                            </div>
                        </div>
                    <?php endif; ?>

                    <div class="vp-tax-tags">
                        <?php foreach ($taxonomy['tags'] as $tag): ?>
                            <?php
                            /*
                             * Neither `attribute_tags` nor `event_tags`
                             * records who applied a tag, so no scope
                             * here can say *who said it* — the tooltip
                             * named the carrying events' creator
                             * organisations once and was withdrawn for
                             * claiming more than it knew.
                             */
                            ?>
                            <span class="vp-tag" title="<?= h($reach(
                                $tag['occurrences'],
                                $tag['events']
                            )) ?>">
                                <?= $this->element(
                                    'genericElementsBS5/Badges/tag',
                                    array(
                                        'tag' => $tag,
                                        'local' => !empty($tag['local']),
                                        'hiddenClass' => '',
                                    )
                                ) ?>
                            </span>
                        <?php endforeach; ?>
                        <?php if (!empty($taxonomy['lead_more'])): ?>
                            <span class="vp-tag-more" title="<?= h(
                                implode(', ', $taxonomy['lead_others'])
                            ) ?>"><?= h(sprintf(
                                __n(
                                    'and %s other label',
                                    'and %s other labels',
                                    $taxonomy['lead_more']
                                ),
                                number_format($taxonomy['lead_more'])
                            )) ?></span>
                        <?php endif; ?>
                    </div>

                </div>
            </div>
        <?php endforeach; ?>

        <?php
        /**
         * One galaxy's clusters, capped, with what was left out said.
         *
         * @param array $galaxy
         * @return string
         */
        $clusters = function ($galaxy) use ($reach) {
            $shown = array_slice(
                $galaxy['clusters'],
                0,
                CLUSTERS_PER_GALAXY
            );
            $more = count($galaxy['clusters']) - count($shown);
            ob_start();
            foreach ($shown as $cluster) {
                ?>
                <span class="vp-tag" title="<?= h($reach(
                    $cluster['occurrences'],
                    $cluster['events']
                )) ?>">
                    <?= $this->TagChip->cluster(array(
                        'id' => isset($cluster['id']) ? $cluster['id'] : null,
                        'value' => $cluster['name'],
                        'galaxy' => $galaxy['galaxy'],
                    ), array('display' => 'leaf')) ?>
                </span>
                <?php
            }
            if ($more > 0) {
                ?>
                <span class="vp-galaxy-more"><?= h(sprintf(
                    __n(
                        'and %s more cluster',
                        'and %s more clusters',
                        $more
                    ),
                    number_format($more)
                )) ?></span>
                <?php
            }
            return ob_get_clean();
        };
        ?>

        <?php if ($flatGalaxies && !empty($galaxies)): ?>
            <div class="vp-tax vp-tax-flat vp-tax-galaxies">
                <div class="vp-tax-body">
                    <div class="vp-tax-tags">
                        <?php foreach ($galaxies as $galaxy): ?>
                            <span class="vp-tax-group">
                                <span class="vp-tax-group-name">
                                    <span class="misp-icon
                                                 misp-icon-galaxy
                                                 misp-simple"></span>
                                    <?= h($galaxy['galaxy']) ?>
                                </span>
                                <?= $clusters($galaxy) ?>
                            </span>
                        <?php endforeach; ?>
                    </div>
                </div>
            </div>
        <?php endif; ?>

        <?php foreach ($flatGalaxies ? array() : $galaxies as $galaxy): ?>
            <div class="vp-tax vp-tax-galaxies">
                <div class="vp-tax-name">
                    <span class="misp-icon misp-icon-galaxy
                                 misp-simple"></span>
                    <?= h($galaxy['galaxy']) ?>
                </div>
                <div class="vp-tax-body">
                    <div class="vp-tax-tags">
                        <?= $clusters($galaxy) ?>
                    </div>
                </div>
            </div>
        <?php endforeach; ?>

    <?php endif; ?>

</div>
