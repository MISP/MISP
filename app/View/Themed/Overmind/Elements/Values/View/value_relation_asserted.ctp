<?php
App::uses('ValueUrlTool', 'Tools/ValueIntelligence');
/**
 * Section three: relationships somebody wrote down on purpose.
 *
 * The rule the whole tab lives or dies by is enforced here by form and
 * not by hue: **a machine relation is a table row, a human claim never
 * is**. Each claim is a `.vp-analyst` block — the same primitive the
 * Overview's analyst preview and the Analyst data tab use — so a claim
 * looks like a claim everywhere on the page, and cannot be mistaken for
 * a row even in greyscale.
 *
 * This section is never ranked and never truncated. Nobody generated
 * these; they were written one at a time, and the only thing that can
 * remove one from the list is a distribution the reader is outside of.
 * That is the inverse of section one's cap, and it is stated as such.
 *
 * Lazily loaded from ValuesController::viewRelationAsserted.
 *
 * @var array $valueIntelligence
 * @var string $valueB64
 */
$profile = $valueIntelligence;
$asserted = $profile['relationships']['asserted'];
$claims = $asserted['claims'];
$view = $this;

/**
 * @param string $text
 * @return string
 */
$slug = function ($text) {
    return trim(preg_replace('/[^a-z0-9]+/', '-', strtolower($text)), '-');
};

/*
 * One glyph per target kind, so the reader can tell an event from a
 * galaxy cluster without reading the word — and the word is there too.
 */
$targetIcons = array(
    'Event' => 'misp-icon misp-icon-event misp-simple',
    'GalaxyCluster' => 'misp-icon misp-icon-galaxy misp-simple',
    'Object' => 'misp-icon misp-icon-object misp-simple',
    'Attribute' => 'misp-icon misp-icon-attribute misp-simple',
    'AttributeValue' => 'misp-icon misp-icon-value-intelligence misp-simple',
);

/*
 * The same kinds in a sentence. `strtolower` on the model name
 * would say *this galaxycluster*.
 */
$kindWords = array(
    'Event' => __('event'),
    'GalaxyCluster' => __('galaxy cluster'),
    'Object' => __('object'),
    'Attribute' => __('attribute'),
    'AttributeValue' => __('value'),
);

/**
 * Where a claim's far end opens.
 *
 * **To the event's own tab and not to `/attributes/view` or
 * `/objects/view`**, which is the choice the sightings table already
 * made for the same reason: this theme's event view takes no `focus:`
 * parameter, and the two flat views redirect to the event and lose
 * which record they were asked about. The link's title carries the
 * record, so what the cell cannot show the hover does.
 *
 * @param array $target
 * @return string|null Null when there is nowhere to send the reader
 */
$targetUrl = function ($target) use ($baseurl) {
    if (empty($target['resolved'])) {
        return null;
    }
    if ($target['kind'] === 'Event') {
        return $baseurl . '/events/view/' . $target['id'];
    }
    if ($target['kind'] === 'GalaxyCluster') {
        return $baseurl . '/galaxy_clusters/view/' . $target['id'];
    }
    if ($target['kind'] === 'AttributeValue') {
        return $baseurl . '/values/view/' . ValueUrlTool::address($target['label']);
    }
    if (empty($target['event'])) {
        return null;
    }
    return $baseurl . '/events/view/' . $target['event']['id']
        . ($target['kind'] === 'Object'
            ? '#tab-objects'
            : '#tab-attributes');
};

/**
 * What that link promises, which is not always the target itself.
 *
 * @param array $target
 * @return string
 */
$targetTitle = function ($target) {
    if ($target['kind'] === 'Event') {
        return sprintf(__('Open event #%s'), $target['id']);
    }
    if ($target['kind'] === 'GalaxyCluster') {
        return __('Open this galaxy cluster');
    }
    if ($target['kind'] === 'AttributeValue') {
        return __('Open this value');
    }
    return sprintf(
        $target['kind'] === 'Object'
            ? __('Object #%1$s, in the Objects tab of event #%2$s')
            : __('Attribute #%1$s, in the Attributes tab of event #%2$s'),
        $target['id'],
        empty($target['event']) ? '?' : $target['event']['id']
    );
};

/**
 * An organisation, linked wherever there is an id to link it by.
 *
 * @param array|null $org
 * @param string $title
 * @return string
 */
$orgChip = function ($org, $title) use ($baseurl) {
    if (empty($org['name'])) {
        return '';
    }
    $glyph = '<i class="fas fa-building me-1"></i>';
    if (empty($org['id'])) {
        return '<span title="' . h($title) . '">' . $glyph
            . h($org['name']) . '</span>';
    }
    return '<a class="vp-claim-link" title="' . h($title) . '" href="'
        . h($baseurl . '/organisations/view/' . $org['id']) . '">'
        . $glyph . h($org['name']) . '</a>';
};

/*
 * The relationship types actually present, for the filter. Offering a
 * type nobody used would be a control that can only empty the list.
 */
$types = array();
foreach ($claims as $claim) {
    $types[$claim['relationship_type']] = true;
}
$types = array_keys($types);
sort($types);

ob_start();
?>
    <select class="form-select form-select-sm w-auto"
            data-vp-filter-key="rel"
            aria-label="<?= __('Relationship type') ?>">
        <option value=""><?= __('All relationship types') ?></option>
        <?php foreach ($types as $type): ?>
            <option value="<?= h($slug($type)) ?>"><?= h($type) ?></option>
        <?php endforeach; ?>
    </select>
<?php
$headerExtra = ob_get_clean();
if (empty($claims)) {
    $headerExtra = null;
}
?>
<div class="card shadow-sm mb-3 vp-panel vp-rel-k-human"
     style="--vp-panel-color: var(--vp-rel-human);"
     data-vp-list
     data-vp-rel-summary="asserted"
     data-vp-rel-count="<?= h(number_format($asserted['total'])) ?>">

    <?php
    ob_start();
    ?>
        <span class="vp-rel-tag me-1">
            <span class="misp-icon misp-icon-analyst-note misp-simple"></span>
            <?= h(__('Asserted')) ?>
        </span>
        <?php if (empty($claims)): ?>
            <?= h(__('No claim')) ?>
        <?php else: ?>
            <?= h(sprintf(
                __('%1$s from %2$s'),
                __n('%d claim', '%d claims', $asserted['total'],
                    $asserted['total']),
                __n('%d organisation', '%d organisations',
                    $asserted['orgs'], $asserted['orgs'])
            )) ?>
        <?php endif; ?>
        &nbsp;·&nbsp;<?= h(__('analyst-data relationships')) ?>&nbsp;·&nbsp;
        <span class="vp-rel-prov vp-rel-prov-human">
            <i class="fas fa-user-pen"></i><?= h(__('Human claim')) ?>
        </span>
    <?php
    $headerSub = ob_get_clean();
    ?>

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('Asserted by analysts'),
        'panelIcon' => 'misp-icon misp-icon-analyst-note misp-simple',
        'panelColor' => 'var(--vp-rel-human)',
        'panelSub' => $headerSub,
        'panelExtra' => $headerExtra,
    )) ?>

    <?php if (empty($claims)): ?>

        <div class="p-3">
            <div class="vp-empty">
                <span class="misp-icon misp-icon-analyst-note
                             misp-simple"></span>
                <span>
                    <?= __('No analyst has asserted a relationship for'
                        . ' this value.') ?>
                </span>
            </div>
        </div>

    <?php else: ?>

        <div class="vp-rel-cap vp-rel-cap-complete">
            <i class="fas fa-user-check"
               title="<?= h(__(
                   'Stays complete even on a value whose events were'
                   . ' too large for In the same events to read.'
               )) ?>"></i>
            <span>
                <?= sprintf(
                    __(
                        '%1$s Written one at a time by people, so'
                        . ' nothing here is ranked or truncated.'
                    ),
                    '<strong>' . h(__n(
                        'The single claim is shown.',
                        'All %d claims are shown.',
                        $asserted['total'],
                        $asserted['total']
                    )) . '</strong>'
                ) ?>
            </span>
        </div>

        <div class="p-3 d-flex flex-column gap-2" data-vp-list-rows>
            <?php foreach ($claims as $claim): ?>
                <?php
                $target = $claim['target'];
                $icon = isset($targetIcons[$target['kind']])
                    ? $targetIcons[$target['kind']]
                    : 'fas fa-cube';
                $outbound = $claim['direction'] === 'outbound';
                $url = $targetUrl($target);
                ?>
                <div class="vp-analyst vp-rel-claim"
                     data-vp-list-row
                     data-vp-facet="rel:<?=
                         h($slug($claim['relationship_type'])) ?>">
                    <div class="vp-analyst-kind">
                        <i class="fas fa-arrow-right-long"></i>
                        <?= h($claim['relationship_type']) ?>
                    </div>
                    <div class="vp-analyst-body">
                        <div class="d-flex align-items-center gap-2
                                    flex-wrap">
                            <?= $this->element(
                                'Values/View/value_relation_direction',
                                array(
                                    'direction' => $claim['direction'],
                                    'directionTitle' => $outbound
                                        ? __('This value is the source of'
                                            . ' the claim')
                                        : __('Something else claims a'
                                            . ' relationship to this value'),
                                )
                            ) ?>
                            <?php if (!empty($claim['spelled'])): ?>
                                <span class="small"
                                      title="<?= h(__('Written on this value in another spelling. MISP shows it with the value you opened, but an accent can make a different domain.')) ?>">
                                    <span class="text-warning-emphasis"><?= __('spelled') ?></span>
                                    <span class="font-monospace"><?= h($claim['spelled']) ?></span>
                                </span>
                            <?php endif; ?>
                            <span class="vp-rel-target">
                                <?php if (strpos($icon, 'misp-icon') === 0): ?>
                                    <span class="<?= h($icon) ?>"></span>
                                <?php else: ?>
                                    <i class="<?= h($icon) ?>"></i>
                                <?php endif; ?>
                                <span class="fw-semibold">
                                    <?= h($target['kind'] === 'AttributeValue' ? __('Value') : $target['kind']) ?>
                                </span>
                                <?php
                                /*
                                 * Beside the thing it describes, and
                                 * *before* its name rather than after
                                 * it. The card opens to the right of
                                 * this glyph, so putting the glyph past
                                 * a label of unbounded length would put
                                 * the card's left edge there too — an
                                 * event title long enough pushed it off
                                 * the viewport below 1024px and gave
                                 * the whole page a horizontal
                                 * scrollbar. Here the glyph's x is
                                 * bounded by the longest kind word.
                                 */
                                ?>
                                <?= $this->element(
                                    'Values/View/value_claim_target_card',
                                    array(
                                        'target' => $target,
                                        'url' => $url,
                                        'kindWords' => $kindWords,
                                    )
                                ) ?>
                                <?php if ($url === null): ?>
                                    <?php
                                    /*
                                     * A UUID and not a name, so it is
                                     * set in the face that says so.
                                     */
                                    ?>
                                    <span class="text-muted <?= $target[
                                        'resolved'] ? '' : 'font-monospace' ?>">
                                        <?= h($target['label']) ?>
                                    </span>
                                <?php else: ?>
                                    <a class="vp-claim-link vp-claim-target"
                                       href="<?= h($url) ?>"
                                       title="<?= h($targetTitle($target)) ?>">
                                        <?= h($target['label']) ?>
                                    </a>
                                <?php endif; ?>
                            </span>
                        </div>
                        <?php if ($claim['text'] !== ''): ?>
                            <div class="vp-analyst-text mt-1">
                                <?= h($claim['text']) ?>
                            </div>
                        <?php endif; ?>
                        <?php
                        /*
                         * What the far end *is*, under what it is
                         * called. Ordered the same way for every kind —
                         * where it lives, what it is, who made it — so
                         * six claims pointing at four kinds of thing
                         * still read down one column.
                         */
                        $facts = array();
                        if (!empty($target['event'])) {
                            $facts[] = '<a class="vp-claim-link" href="'
                                . h($baseurl . '/events/view/'
                                    . $target['event']['id'])
                                . '" title="' . h(__('Open the event'))
                                . '">' . h(sprintf(
                                    '#%s %s',
                                    $target['event']['id'],
                                    $target['event']['info']
                                )) . '</a>';
                        }
                        foreach ($target['facts'] as $fact) {
                            $facts[] = h($fact);
                        }
                        $facts[] = $orgChip(
                            $target['org'],
                            sprintf(
                                __('The organisation that created this %s'),
                                isset($kindWords[$target['kind']])
                                    ? $kindWords[$target['kind']]
                                    : $target['kind']
                            )
                        );
                        $facts = array_filter($facts);
                        ?>
                        <?php if (!$target['resolved']): ?>
                            <?php
                            /*
                             * Two reasons, one line, and the panel does
                             * not know which: `getRelatedElement` and
                             * `fetchGalaxyClusters` are both ACL'd, so
                             * an empty answer means gone *or* not
                             * yours. Naming both is what §14.6 allows —
                             * the claim itself is already visible, and
                             * this says nothing about whether the thing
                             * it names exists.
                             */
                            ?>
                            <div class="vp-claim-facts vp-claim-unresolved">
                                <i class="fas fa-circle-question"></i>
                                <span>
                                    <?= __('Not held on this instance, or'
                                        . ' not visible to you — the claim'
                                        . ' is shown by the UUID it names.')
                                    ?>
                                </span>
                            </div>
                        <?php elseif (!empty($facts)): ?>
                            <div class="vp-claim-facts">
                                <i class="fas fa-turn-up fa-rotate-90"></i>
                                <span>
                                    <?= implode(
                                        ' <span class="vp-claim-sep">·</span> ',
                                        $facts
                                    ) ?>
                                </span>
                            </div>
                        <?php endif; ?>
                        <div class="vp-analyst-meta d-flex align-items-center
                                    gap-2 flex-wrap">
                            <?php
                            /*
                             * Named, now that a second organisation can
                             * appear two lines above it. `ADMIN` beside
                             * a date said nothing about which of the
                             * two it was.
                             */
                            ?>
                            <span>
                                <?= sprintf(
                                    __('Asserted by %s'),
                                    $orgChip(
                                        array(
                                            'id' => $claim['org_id'],
                                            'name' => $claim['org'],
                                        ),
                                        __('The organisation credited with'
                                            . ' writing this claim')
                                    )
                                ) ?>
                            </span>
                            <?php if ($claim['owner'] !== null): ?>
                                <?php
                                /*
                                 * Only when the two columns differ,
                                 * which on an instance nothing has
                                 * synced into is never. A claim that
                                 * arrived over a sync is owned by the
                                 * organisation that passed it on and
                                 * credited to the one that wrote it.
                                 */
                                ?>
                                <span>·</span>
                                <span>
                                    <?= sprintf(
                                        __('held by %s'),
                                        $orgChip(
                                            array(
                                                'id' => $claim['owner_id'],
                                                'name' => $claim['owner'],
                                            ),
                                            __('The organisation this'
                                                . ' instance holds the'
                                                . ' claim for')
                                        )
                                    ) ?>
                                </span>
                            <?php endif; ?>
                            <span>·</span>
                            <span class="font-monospace"
                                  title="<?= h(__('Last modified')) ?>">
                                <?= h($claim['date']) ?>
                            </span>
                            <?= $this->element(
                                'genericElementsBS5/Badges/distribution',
                                array(
                                    'distribution' =>
                                        (int)$claim['distribution'],
                                    'full' => false,
                                )
                            ) ?>
                        </div>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>

        <div class="px-3 pb-3 d-none" data-vp-list-empty>
            <div class="vp-empty vp-empty-inline">
                <i class="fas fa-filter"></i>
                <span>
                    <?= __('Nobody has asserted a relationship of that'
                        . ' type for this value.') ?>
                </span>
            </div>
        </div>

        <div class="px-3 pb-3 d-flex align-items-center gap-2 flex-wrap">
            <span class="small text-muted vp-min-w-0">
                <?= h(sprintf(
                    __(
                        'A claim is written against one occurrence of'
                        . ' this value; this lists the claims on all'
                        . ' %d.'
                    ),
                    $asserted['occurrences']
                )) ?>
                <?php if (!empty($asserted['capped'])): ?>
                    <?php
                    /*
                     * The cap is on the *lookup*, not on the list. A
                     * claim written against an occurrence outside the
                     * most recent N would not be found, and a section
                     * whose whole argument is *never truncated* has to
                     * name the one place it can still miss something.
                     */
                    ?>
                    <?= h(sprintf(
                        __(
                            'Those are the %d most recent; a claim'
                            . ' written against an older occurrence of'
                            . ' this value is not looked up.'
                        ),
                        $asserted['occurrences']
                    )) ?>
                <?php endif; ?>
                <?php if (!empty($asserted['prose_absent'])): ?>
                    <?php
                    /*
                     * Said once here rather than as a placeholder on
                     * every block: a claim's prose is not missing data,
                     * it is data MISP does not model.
                     */
                    ?>
                    <?= __('MISP stores no text on a relationship, so no'
                        . ' claim here has a description.') ?>
                <?php endif; ?>
            </span>
        </div>

    <?php endif; ?>

    <?php
    /*
     * §14.6, applied here by phase 24. This carried a `.vp-acl-note`
     * counting the claims held at a distribution the reader is outside
     * of — *"their existence is counted; their text and their target
     * are not shown"*. Counting the existence is exactly the disclosure
     * §14.6 forbids, on a page whose URL takes any value the reader
     * types, so the band is gone and the list simply is what the reader
     * may see.
     */
    ?>

</div>
