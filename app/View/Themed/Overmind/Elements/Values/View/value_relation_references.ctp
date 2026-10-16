<?php
/**
 * Section six: MISP's own typed relation between two objects.
 *
 * The other five notions on this tab are derived — a shared event, a
 * shared object, a CIDR containment, a feed cache hit. This one and the
 * asserted claims are the two somebody **wrote**, and they are written
 * about different things: a claim is an analyst's statement about a
 * value, and a reference is a structural fact about an object. Keeping
 * them in separate sections is §5's separation applied to the two human
 * notions rather than only to the machine ones.
 *
 * Three things this section is careful about:
 *
 *   both depths       a reference can point at this value's own
 *                     attribute, or at the object it sits in. Reading
 *                     only the second would miss the case that carries
 *                     `24-relationships.md` §25.3's bridge, where ten
 *                     `hosted-by` references point at one bare address.
 *   both directions   `hosted-by` reads one way and the row says which.
 *                     An inbound reference is somebody else's object
 *                     naming this value; an outbound one is this
 *                     value's object naming something else.
 *   self is not a     `18.117.184.102` sits in four `passive-dns`
 *   relation          objects and each carries a `hosted-by` back to
 *                     the bare attribute. Those are the value pointing
 *                     at itself and they are dropped — they would have
 *                     been eight of twelve rows.
 *
 * The relationship type is printed **verbatim**. `hosted-by` and
 * `communicates-with` are MISP's own vocabulary; `Crush` and `Co-worker`
 * are on the verification instance because somebody typed them, and a
 * panel that normalised those would be hiding what the data says.
 *
 * Lazily loaded from ValuesController::viewRelationReferences.
 *
 * @var array $valueIntelligence
 * @var string $valueB64
 */
$references = $valueIntelligence['relationships']['references'];
$rows = $references['rows'];

$icon = 'fas fa-diagram-project';
?>
<div class="card shadow-sm mb-3 vp-panel vp-rel-k-reference"
     style="--vp-panel-color: var(--vp-rel-reference);"
     id="vp-relation-references"
     data-vp-list
     data-vp-rel-summary="references"
     data-vp-rel-count="<?= h(number_format($references['total'])) ?>">

    <?php
    ob_start();
    ?>
        <span class="vp-rel-tag me-1">
            <i class="<?= h($icon) ?>"></i><?= h(__('Object relationships')) ?>
        </span>
        <?php if (!empty($rows)): ?>
            <?= h(sprintf(
                __('%1$s across %2$s'),
                __n('%d reference', '%d references', $references['total'],
                    $references['total']),
                __n('%d relationship type', '%d relationship types',
                    count($references['types']),
                    count($references['types']))
            )) ?>
            &nbsp;·&nbsp;
        <?php endif; ?>
        <span class="vp-rel-prov vp-rel-prov-human">
            <i class="fas fa-user-pen"></i><?= h(__('Human claim')) ?>
        </span>
        &nbsp;·&nbsp;<?= h(__('ObjectReference')) ?>
    <?php
    $headerSub = ob_get_clean();
    ?>

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('Object relationships'),
        'panelIcon' => $icon,
        'panelColor' => 'var(--vp-rel-reference)',
        'panelSub' => $headerSub,
    )) ?>

    <div class="vp-rel-cap">
        <i class="fas fa-circle-info"
           title="<?= h(__(
               'Rows reach this value directly, at one of its own'
               . ' attributes, or through an object it sits in. A'
               . ' reference pointing back at this value is not'
               . ' listed — it relates the value to itself.'
           )) ?>"></i>
        <span>
            <?= __('A reference is a typed link between two objects,'
                . ' written by whoever wrote the event.') ?>
        </span>
    </div>

    <div class="p-3">

        <?php if (empty($rows)): ?>

            <div class="vp-empty">
                <i class="<?= h($icon) ?>"></i>
                <span>
                    <?php if ($references['read_objects'] === 0
                        && $references['occurrences'] === 0
                    ): ?>
                        <?= __('No occurrence of this value that you can see, so there is nothing for a reference to point at.') ?>
                    <?php elseif ($references['with_references'] > 0): ?>
                        <?= h(sprintf(
                            __n(
                                'One of this value\'s objects carries a reference, and it points back at this value rather than at anything else.',
                                '%s of this value\'s objects carry a reference, and every one of them points back at this value rather than at anything else.',
                                $references['with_references']
                            ),
                            number_format($references['with_references'])
                        )) ?>
                    <?php else: ?>
                        <?= h(sprintf(
                            __n(
                                'Nothing references this value, and the one object it sits in references nothing. That is the ordinary case — references are written by hand and most objects carry none.',
                                'Nothing references this value, and none of the %s objects it sits in references anything. That is the ordinary case — references are written by hand and most objects carry none.',
                                $references['read_objects']
                            ),
                            number_format($references['read_objects'])
                        )) ?>
                    <?php endif; ?>
                </span>
            </div>

        <?php else: ?>

            <div class="table-responsive" data-vp-list-rows>
                <table class="table table-sm table-hover vp-table
                              align-middle mb-0">
                    <thead>
                        <tr>
                            <th scope="col"><?= __('Relationship') ?></th>
                            <th scope="col"><?= __('Reaches this value') ?></th>
                            <th scope="col"><?= __('The other end') ?></th>
                            <th scope="col"><?= __('Its values') ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($rows as $row): ?>
                            <?php
                            $inbound = $row['direction'] === 'inbound';
                            $far = $row['far'];
                            /*
                             * One destination for the whole far end,
                             * built once here because two cells open
                             * it: the chip that names the record, and
                             * every one of its values beside it.
                             *
                             * **To the themed event view's tab** and
                             * not to `/objects/view`, which redirects
                             * to `/events/view` — the *unthemed* event
                             * page, a worse place to land than the tab,
                             * and it loses which record it was asked
                             * about on the way. This theme's view takes
                             * no `focus:`, so the title carries the
                             * record's own id;
                             * `value_relation_asserted.ctp` and the
                             * near-match panel reached this URL the
                             * same way for the same reason.
                             *
                             * The tab follows `kind` and not the chip:
                             * a far end that is an attribute *inside*
                             * an object still shows the object's name —
                             * that is where the reader will recognise
                             * it — but the reference points at the
                             * attribute, so that is the tab it opens.
                             */
                            $farIsObject = $far['kind'] === 'object';
                            $farUrl = $baseurl . '/events/view/'
                                . $far['event']
                                . ($farIsObject
                                    ? '#tab-objects'
                                    : '#tab-attributes');
                            $farTitle = $farIsObject
                                ? sprintf(
                                    __('%1$s object %2$s in event %3$s'),
                                    $far['object'],
                                    $far['id'],
                                    $far['event']
                                )
                                : sprintf(
                                    __('Attribute %1$s in event %2$s'),
                                    $far['id'],
                                    $far['event']
                                );
                            ?>
                            <tr class="vp-rel-stripe vp-rel-k-reference">
                                <td>
                                    <span class="<?= $row['named']
                                        ? 'vp-ref-type'
                                        : 'vp-ref-unnamed' ?>">
                                        <?= h($row['relationship']) ?>
                                    </span>
                                    <?php if ($row['comment'] !== ''): ?>
                                        <div class="vp-fact-line-sub
                                                    vp-rel-cell"
                                             title="<?= h($row['comment']) ?>">
                                            <?= h($row['comment']) ?>
                                        </div>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?= $this->element(
                                        'Values/View/value_relation_direction',
                                        array(
                                            'direction' => $row['direction'],
                                            'directionTitle' => $inbound
                                                ? __('Somebody else\'s object'
                                                    . ' names this value')
                                                : __('An object this value'
                                                    . ' sits in names'
                                                    . ' something else'),
                                        )
                                    ) ?>
                                    <div class="vp-fact-line-sub">
                                        <?php if ($row['near']['kind']
                                            === 'attribute'
                                        ): ?>
                                            <?= h(__('directly, at this attribute')) ?>
                                        <?php else: ?>
                                            <?= h(sprintf(
                                                __('through its %s object'),
                                                $row['near']['object'] === null
                                                    ? __('parent')
                                                    : $row['near']['object']
                                            )) ?>
                                            <?php if ($row['near']['relation']
                                                !== ''
                                            ): ?>
                                                <span class="font-monospace">
                                                    · <?= h(
                                                        $row['near']['relation']
                                                    ) ?>
                                                </span>
                                            <?php endif; ?>
                                        <?php endif; ?>
                                    </div>
                                </td>
                                <td>
                                    <?php
                                    /*
                                     * The record at the far end of the
                                     * reference — the same cell
                                     * `value_relation_near_match.ctp`
                                     * builds for a matched record, and
                                     * it goes to the same place. The
                                     * URL and title are built in the
                                     * row preamble, which is where the
                                     * choice of destination is argued.
                                     */
                                    ?>
                                    <?php if ($far['object'] !== null): ?>
                                        <a class="vp-rel-tag"
                                           href="<?= h($farUrl) ?>"
                                           title="<?= h($farTitle) ?>">
                                            <i class="fas fa-cube"></i><?=
                                                h($far['object']) ?>
                                        </a>
                                    <?php else: ?>
                                        <span class="vp-rel-tag">
                                            <i class="fas fa-tag"></i><?=
                                                h(__('attribute')) ?>
                                        </span>
                                    <?php endif; ?>
                                    <div class="vp-fact-line-sub">
                                        <a href="<?= h($baseurl) ?>/events/view/<?=
                                            h($far['event']) ?>"
                                           class="font-monospace small">
                                            #<?= h($far['event']) ?>
                                        </a>
                                    </div>
                                </td>
                                <td>
                                    <?php
                                    /*
                                     * The far object's identifying
                                     * values. §25.3's whole reading is
                                     * that the object on the other end
                                     * of a `hosted-by` names a brand
                                     * this value's page never mentions,
                                     * and the reader who sees that name
                                     * wants the object it was written
                                     * in — so each one opens the record
                                     * it is stored on, which is the
                                     * chip's destination beside it.
                                     * A value's own page is about to be
                                     * one gesture away from any string
                                     * on the page; the event is not.
                                     */
                                    ?>
                                    <div class="vp-ref-faces">
                                        <?php foreach ($far['values']
                                            as $entry): ?>
                                            <a class="vp-ref-face"
                                               href="<?= h($farUrl) ?>"
                                               title="<?= h(sprintf(
                                                   __('%1$s, on %2$s'),
                                                   trim(
                                                       $entry['relation']
                                                       . ' '
                                                       . $entry['value']
                                                   ),
                                                   $farTitle
                                               )) ?>">
                                                <?php if ($entry['relation']
                                                    !== ''
                                                ): ?>
                                                    <span class="vp-ref-face-relation"><?=
                                                        h($entry['relation'])
                                                    ?>:</span>
                                                <?php endif; ?>
                                                <?= h($entry['value']) ?>
                                            </a>
                                        <?php endforeach; ?>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

            <div class="px-1 py-2 border-top">
                <?= $this->element('Values/View/value_pager', array(
                    'size' => $references['page_size'],
                    'shown' => count($rows),
                    'total' => $references['total'],
                    'noun' => array(
                        'one' => __('reference'),
                        'many' => __('references'),
                    ),
                )) ?>
            </div>

        <?php endif; ?>

        <?php
        /*
         * The coverage sentence, and it is about this value rather than
         * about the instance. "7,905 of 69,976 objects carry a
         * reference" is true and costs two counts over the whole
         * database to print; "four of this value's four objects carry
         * one" is the number a reader of this page is asking about.
         */
        ?>
        <div class="vp-fact-line-sub mt-2">
            <i class="fas fa-ruler-horizontal"></i>
            <?= h(sprintf(
                __('Read from %1$s and %2$s of this value.'),
                sprintf(
                    __n('%s occurrence', '%s occurrences',
                        $references['occurrences'],
                        number_format($references['occurrences'])),
                    number_format($references['occurrences'])
                ),
                sprintf(
                    __n('%s object', '%s objects',
                        $references['read_objects'],
                        number_format($references['read_objects'])),
                    number_format($references['read_objects'])
                )
            )) ?>
            <?= $references['with_references'] === 0
                ? h(__('None of those objects carries a reference at all.'))
                : h(sprintf(
                    __n(
                        'One of them carries a reference.',
                        '%s of them carry a reference.',
                        $references['with_references']
                    ),
                    number_format($references['with_references'])
                )) ?>
            <?php if (!empty($references['cap']['applied'])): ?>
                <?= h(sprintf(
                    __('The object read stops at %s, so a reference on an older object is not on this list.'),
                    number_format($references['cap']['limit'])
                )) ?>
            <?php endif; ?>
        </div>

    </div>

</div>
