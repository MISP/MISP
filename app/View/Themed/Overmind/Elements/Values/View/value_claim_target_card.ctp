<?php
/**
 * The hover card beside a claim's far end.
 *
 * **It is about the target and nothing else.** The claim's own record —
 * its type, its author, its date, its audience — is on the row already,
 * and a card that repeated it made the reader read the same four facts
 * twice to reach the one thing they came for.
 *
 * Two sections at most: what the target is, and — for an attribute or an
 * object, which are always inside one — the event it sits in. An event
 * target has no second section, because it is the event.
 *
 * **Rows are stored columns.** That rule is what admits `to_ids`,
 * `attribute_count` and `template_version`, and what keeps the card from
 * drifting into commentary about the claim.
 *
 * **CSS on `:hover` and `:focus-within`, not `data-bs-toggle`.** This
 * panel arrives through `loadAjaxContainer`, and MISP's only Bootstrap
 * tooltip initialiser runs once at `DOMContentLoaded` — a tooltip
 * declared here would silently never bind. CSS has no such lifecycle and
 * reaches the keyboard, which a native `title` does not.
 *
 * @var array $target
 * @var string|null $url Where the target opens, or null
 * @var array $kindWords Model name => the word for it in a sentence
 */
$view = $this;

/**
 * @param string $text
 * @return string
 */
$head = function ($text) {
    return '<div class="vp-claim-tiphead">' . h($text) . '</div>';
};

/**
 * @param string $label
 * @param string $html Already escaped, or built from escaped parts
 * @param string $class
 * @return string Empty when there is no value, so the row does not draw
 */
$raw = function ($label, $html, $class = '') {
    if ($html === '' || $html === null) {
        return '';
    }
    return '<div class="vp-claim-tiprow"><b>' . h($label) . '</b>'
        . '<span class="' . h($class) . '">' . $html . '</span></div>';
};

/**
 * @param string $label
 * @param string|null $value
 * @param string $class
 * @return string
 */
$row = function ($label, $value, $class = '') use ($raw) {
    return $raw($label, $value === null ? '' : h($value), $class);
};

/**
 * The audience in words rather than as the row's bare glyph.
 *
 * @param int|null $level
 * @return string
 */
$audience = function ($level) use ($view) {
    if ($level === null) {
        return '';
    }
    return $view->element(
        'genericElementsBS5/Badges/distribution',
        array('distribution' => (int)$level, 'full' => true)
    );
};

/**
 * What an event was labelled with. MISP's own tag badge, so a tag looks
 * the same here as on the event page.
 *
 * @param array $tags
 * @return string
 */
$tagChips = function ($tags) use ($view) {
    $out = '';
    foreach ($tags as $tag) {
        $out .= $view->element(
            'genericElementsBS5/Badges/tag',
            array(
                'tag' => $tag,
                'local' => false,
                'hiddenClass' => '',
                'showFavourite' => false,
            )
        );
    }
    return $out;
};

/**
 * A galaxy cluster, named rather than left as the tag string that
 * stores it — `misp-galaxy:threat-actor="TAG-53"` is not a label.
 *
 * @param array $clusters
 * @return string
 */
$clusterChips = function ($clusters) use ($view) {
    return $view->TagChip->clusters($clusters, array(
        'href' => function () {
            return null;
        },
    ));
};

/**
 * One event, said the same way wherever it is drawn.
 *
 * @param array $event
 * @return string
 */
$eventBlock = function ($event) use ($row, $raw, $audience, $tagChips,
    $clusterChips
) {
    $out = '';
    foreach ($event['detail'] as $label => $value) {
        $out .= $row($label, $value);
    }
    $out .= $raw(__('Audience'), $audience($event['distribution']));
    /*
     * The count in the label, because the chip list scrolls past a few
     * rows and a reader who cannot see the bottom of it has no way to
     * know whether they are looking at four labels or forty.
     */
    $out .= $raw(
        sprintf(__('Tags (%d)'), count($event['tags'])),
        $tagChips($event['tags']),
        'vp-claim-chips'
    );
    $out .= $raw(
        sprintf(__('Clusters (%d)'), count($event['clusters'])),
        $clusterChips($event['clusters']),
        'vp-claim-chips'
    );
    $out .= $row(__('UUID'), $event['uuid'], 'font-monospace');
    return $out;
};

$kindWord = isset($kindWords[$target['kind']])
    ? $kindWords[$target['kind']]
    : $target['kind'];
?>
<span class="vp-claim-tipwrap">
    <button type="button" class="vp-claim-more"
            aria-label="<?= h(sprintf(
                __('Everything recorded about this %s'),
                $kindWord
            )) ?>">
        <i class="fas fa-circle-info"></i>
    </button>
    <div class="vp-claim-tip" role="tooltip">

        <?= $head($kindWord) ?>
        <?php if (!$target['resolved']): ?>
            <?php
            /*
             * An unresolved target's label *is* its UUID, so naming it
             * as a `Target` row too would fill two rows with one fact.
             * Both reasons are given because the two readers behind it
             * are ACL'd and neither is knowable from here.
             */
            ?>
            <?= $row(__('Status'), __('not held here, or not visible'
                . ' to you')) ?>
        <?php else: ?>
            <?php foreach ($target['detail'] as $label => $value): ?>
                <?= $row($label, $value) ?>
            <?php endforeach; ?>
            <?= $raw(__('Audience'), $audience($target['distribution'])) ?>
            <?= $raw(
                sprintf(__('Tags (%d)'), count($target['tags'])),
                $tagChips($target['tags']),
                'vp-claim-chips'
            ) ?>
            <?= $raw(
                sprintf(__('Clusters (%d)'), count($target['clusters'])),
                $clusterChips($target['clusters']),
                'vp-claim-chips'
            ) ?>
        <?php endif; ?>
        <?= $row($target['kind'] === 'AttributeValue' ? __('SHA-256') : __('UUID'), $target['uuid'], 'font-monospace') ?>

        <?php if (!empty($target['event'])): ?>
            <?php
            /*
             * An attribute and an object are always inside an event, and
             * whether a claim matters usually turns on which event that
             * is — its date, how far along the analysis is, and what it
             * was labelled with.
             */
            ?>
            <?= $head(sprintf(__('In event #%s'),
                $target['event']['id'])) ?>
            <?= $row(__('Info'), $target['event']['info']) ?>
            <?= $eventBlock($target['event']) ?>
        <?php endif; ?>

    </div>
</span>
