<?php
/**
 * A palette: every signal, escalation or exclusion this instance has
 * or this profile names, one row each.
 *
 * The three are one table because they are one shape — an id, a state,
 * a switch and a handful of settings whose keys differ per row. What
 * differs is the last column: only signals have a contribution, because
 * only signals emit a ledger row.
 *
 * **A row's settings are chips, and the chip holds the input.** The
 * points map has no fixed schema by design, so a column per key is not
 * available; a form row per key would make the table four screens long.
 * The chip keeps the density and still edits.
 *
 * @var array $block
 * @var bool $editable
 * @var string $sectionId
 * @var array|null $ledger Signal id => contribution, when a value is
 *                         on the bench
 * @var string|null $benchValue
 */
App::uses('AnalystProfileFormTool', 'Tools/AnalystProfile');
App::uses('ValueLean', 'Tools/ValueIntelligence');

$ledger = isset($ledger) ? $ledger : array();
$benchValue = isset($benchValue) ? $benchValue : null;
$lean = isset($lean) ? $lean : null;
/*
 * Which way the direction pair points on this table. `--vp-dir-with`
 * means *with the lean*, so on a benign record the row that agrees
 * with it is the green one — the same swap the value page puts on every
 * assessment card, from the same helper, because the two surfaces show
 * the same contributions and must read the same way.
 */
$directionStyle = $lean === null
    ? ''
    : ValueLean::directionStyle($lean);
$isSignals = $sectionId === 'signals';
$groups = isset($block['groups']) ? $block['groups'] : array();

/*
 * Grouped only where the document groups: a signal declares its ledger
 * group and the ledger is read group by group, so the palette that
 * edits it reads the same way. Escalations and exclusions have no
 * grouping to honour.
 */
$rows = array();
if ($isSignals) {
    foreach ($groups as $group) {
        $rows[$group] = array();
    }
    foreach ($block['items'] as $item) {
        $group = isset($item['group']) && $item['group'] !== null
            ? $item['group']
            : __('Ungrouped');
        if (!isset($rows[$group])) {
            $rows[$group] = array();
        }
        $rows[$group][] = $item;
    }
} else {
    $rows[''] = $block['items'];
}

/*
 * Two chip columns, named for what they actually hold.
 *
 * *Settings* and *What it reads* were each one word too broad: both
 * columns held settings, and the second mixed the `config` map with the
 * data source being read — which is a property of the implementation,
 * not something on the form. The source moved to the name column with
 * the rest of the signal's identity, and each header now names its own
 * map: `points` is what a reading is worth, `config` is every other
 * knob on it.
 *
 * **Not "thresholds"**, though most of them are: `named` sets how many
 * organisations the evidence line lists, and `stale_factor` is a
 * multiplier — so a header promising thresholds would be wrong about
 * the two keys a reader is most likely to be surprised by. *Tuning*
 * is true of all nine. It also keeps the word *thresholds* meaning the
 * section in the rail, which is a different thing at a different scope.
 *
 * Only signals have a `points` map; an escalation's settings are its
 * `when` conditions and an exclusion's are its own schema, so for those
 * the points column was an em-dash on every row and is not drawn.
 */
$pointsHead = __('Points');
if ($sectionId === 'escalations') {
    $settingsHead = __('When it fires');
} elseif ($sectionId === 'exclusions') {
    $settingsHead = __('Settings');
} else {
    $settingsHead = __('Tuning');
}
$columns = $isSignals ? 5 : 3;
?>
<table class="wb-tbl"<?= $directionStyle === ''
    ? '' : ' style="' . h($directionStyle) . '"' ?>>
    <thead>
        <tr>
            <th style="width:2.2rem"></th>
            <th style="width:<?= $isSignals ? '31%' : '46%' ?>">
                <?= $isSignals ? h(__('Signal')) : h(__('Rule')) ?>
            </th>
            <?php if ($isSignals): ?>
                <th style="width:26%"><?= h($pointsHead) ?></th>
            <?php endif; ?>
            <th style="width:<?= $isSignals ? '21%' : '48%' ?>">
                <?= h($settingsHead) ?>
            </th>
            <?php if ($isSignals): ?>
                <th class="r" style="width:12%">
                    <?= $benchValue === null
                        ? h(__('Contribution'))
                        : h(sprintf(__('On %s'), $benchValue)) ?>
                    <?php
                    /*
                     * What a `+` is *toward*. A column of signed,
                     * coloured numbers with the answer only in the
                     * other pane is a column a reader has to be told
                     * how to read, so it says so where they are
                     * looking.
                     *
                     * It used to read *+ toward <lean>*, which was the
                     * anchoring's claim and true of every row until
                     * `review-2026-09-13.md` §D1. Nine of the eleven
                     * shipped signals weigh the record and their sign
                     * does not move with the verdict, so naming the
                     * lean here told an analyst the opposite of what
                     * the column does. The two exceptions are badged
                     * *reads the value* on their own rows, with the
                     * scored-against-the-verdict sentence in the
                     * badge's title — which is the right altitude for
                     * a rule that applies to two rows out of eleven.
                     *
                     * The wording is the value page's own
                     * (`value_verdict_ledger.ctp`), so the two
                     * surfaces teach one vocabulary.
                     */
                    ?>
                    <?php
                    /*
                     * Always drawn, hidden when empty: the recompute
                     * rewrites it, and a node that is sometimes absent
                     * is a node the update has to create rather than
                     * fill. It no longer varies with the lean, but a
                     * `none` lean has no ledger at all and so no
                     * column to caption.
                     */
                    $anchor = $lean !== null && $lean !== 'none'
                        ? __('+ carries it')
                        : '';
                    ?>
                    <div class="wb-tbl-sub" data-ap-anchor
                         title="<?= h(__(
                             'Plus: the record carries something.'
                             . ' Minus: it does not.'
                         )) ?>"
                         <?= $anchor === '' ? 'hidden' : '' ?>><?=
                        h($anchor) ?></div>
                </th>
            <?php endif; ?>
        </tr>
    </thead>
    <tbody>
    <?php foreach ($rows as $group => $items): ?>
        <?php if ($group !== ''): ?>
            <tr class="wb-grp"><td colspan="<?= $columns ?>"><?= h($group) ?></td></tr>
        <?php endif; ?>
        <?php foreach ($items as $item): ?>
            <?php
            $state = isset($item['state']) ? $item['state'] : 'active';
            $rowClass = '';
            if ($state === 'missing') {
                $rowClass = 'is-off';
            } elseif (!$item['enabled']) {
                $rowClass = 'is-off';
            }
            $contribution = $isSignals && isset($ledger[$item['id']])
                ? $ledger[$item['id']]
                : null;

            /*
             * The row's own control comes out of the field list, so the
             * checkbox is not drawn twice as a chip. Everything else is
             * a chip, grouped by the map it writes to.
             */
            $switch = null;
            $chips = array();
            $seen = array();
            foreach ($item['fields'] as $field) {
                $address = implode('.', $field['path']);
                if (isset($seen[$address])) {
                    continue;
                }
                $seen[$address] = true;
                if ($field['key'] === 'enabled' && $field['type'] === 'bool') {
                    $switch = $field;
                    continue;
                }
                $map = isset($field['map']) ? $field['map'] : '';
                $chips[$map === 'points' ? 'points' : 'config'][] = $field;
            }
            ?>
            <?php
            /*
             * The state travels with the row because the switch can
             * change how the row should read without a reload, and the
             * script is not allowed to guess which dimmed rows it may
             * undim: `missing` is a fact about the instance, and
             * ticking a box cannot change it.
             */
            ?>
            <tr class="<?= h($rowClass) ?>" data-ap-item="<?= h($item['id']) ?>"
                data-ap-state="<?= h($state) ?>">
                <td>
                    <?php if ($switch !== null): ?>
                        <?= $this->element('AnalystProfiles/field', array(
                            'field' => $switch,
                            'editable' => $editable,
                        )) ?>
                    <?php endif; ?>
                </td>
                <td>
                    <div class="wb-id fw-semibold"><?= h($item['title']) ?></div>
                    <?php foreach ($item['badges'] as $badge): ?>
                        <div class="mt-1">
                            <span class="pill t-missing"
                                  title="<?= h($badge['title']) ?>">
                                <?= h($badge['label']) ?>
                            </span>
                        </div>
                    <?php endforeach; ?>
                    <?php if ($state === 'available'): ?>
                        <div class="mt-1">
                            <span class="pill t-plain"
                                  title="<?= h(__('This instance has this'
                                      . ' signal and this profile does not'
                                      . ' use it.')) ?>">
                                <?= h(__('available')) ?>
                            </span>
                        </div>
                    <?php endif; ?>
                    <?php if (!empty($item['emits'])): ?>
                        <div class="wb-sub"><?= h(sprintf(
                            __('Forces the lean to %s when it fires.'),
                            $item['emits']
                        )) ?></div>
                    <?php endif; ?>
                    <?php
                    $help = $isSignals && isset($item['help'])
                        ? $item['help'] : null;
                    ?>
                    <?php if (!empty($item['description'])
                        || $help !== null): ?>
                        <div class="wb-sub">
                            <?= h((string)$item['description']) ?>
                            <?php if ($help !== null): ?>
                                <button type="button" class="sig-more"
                                        data-ap-help aria-haspopup="dialog"
                                        aria-expanded="false">
                                    <i class="fa-solid fa-circle-question"
                                       aria-hidden="true"></i><?=
                                    h(__('How it works')) ?>
                                </button>
                                <template class="sig-help-tpl"><?=
                                    $this->element(
                                        'AnalystProfiles/signal_help',
                                        array(
                                            'signalId' => $item['id'],
                                            'help' => $help,
                                            'trustWeighted' => !empty(
                                                $item['trust_weighted']
                                            ),
                                        )
                                    ) ?></template>
                            <?php endif; ?>
                        </div>
                    <?php endif; ?>
                    <?php
                    /*
                     * What the row *is*, as against what it is set to:
                     * the multiplier its contribution passes through,
                     * and the layer it comes from. Neither is on the
                     * form, so neither is a chip — tags are square where the
                     * state pills are round, which is the whole reason
                     * they can sit in the same cell without being read
                     * as the same kind of thing.
                     */
                    ?>
                    <?php if (!empty($item['trust_weighted'])
                        || !empty($item['layer'])): ?>
                        <div class="sig-meta">
                            <?php if (!empty($item['trust_weighted'])): ?>
                                <?php
                                /*
                                 * No `×`. It is the remove glyph three
                                 * times over on this page — the chip
                                 * drop, the map row's button, and the
                                 * one the JS writes for a new chip —
                                 * so a lone leading one beside those
                                 * chips reads as a control that turns
                                 * the weighting off. Here there is no
                                 * second operand to make it read as
                                 * arithmetic, and *weighted* already
                                 * says the points are scaled.
                                 */
                                ?>
                                <span class="sig-tag is-mult"
                                      title="<?= h(__('Every point this signal'
                                          . ' contributes is multiplied by how'
                                          . ' much the reporting organisation'
                                          . ' is trusted.')) ?>">
                                    <?= h(__('trust weighted')) ?>
                                </span>
                            <?php endif; ?>
                            <?php if (!empty($item['layer'])): ?>
                                <?php
                                /*
                                 * What the rule touches, not what the
                                 * code calls the hook it hangs on.
                                 * `row_filter` is an accurate name for
                                 * a mechanism and no answer at all to
                                 * *does this move one list or every
                                 * count*, which is the difference an
                                 * analyst is surprised by.
                                 */
                                $layer = !empty($item['layer_label'])
                                    ? $item['layer_label']
                                    : $item['layer'];
                                ?>
                                <span class="sig-tag"
                                      <?= empty($item['layer_title'])
                                          ? ''
                                          : 'title="'
                                              . h($item['layer_title'])
                                              . '"' ?>>
                                    <span class="k"><?= h(__('applies to')) ?></span>
                                    <b><?= h($layer) ?></b>
                                </span>
                            <?php endif; ?>
                        </div>
                    <?php endif; ?>
                </td>
                <?php if ($isSignals): ?>
                    <td>
                        <?php if (empty($chips['points'])): ?>
                            <span class="wb-sub">&mdash;</span>
                        <?php endif; ?>
                        <?php foreach ((array)(isset($chips['points'])
                            ? $chips['points'] : array()) as $field): ?>
                            <?= $this->element('AnalystProfiles/chip', array(
                                'field' => $field,
                                'editable' => $editable,
                            )) ?>
                        <?php endforeach; ?>
                    </td>
                <?php endif; ?>
                <td>
                    <?php if (empty($chips['config'])): ?>
                        <span class="wb-sub">&mdash;</span>
                    <?php endif; ?>
                    <?php foreach ((array)(isset($chips['config'])
                        ? $chips['config'] : array()) as $field): ?>
                        <?= $this->element('AnalystProfiles/chip', array(
                            'field' => $field,
                            'editable' => $editable,
                        )) ?>
                    <?php endforeach; ?>
                </td>
                <?php if ($isSignals): ?>
                    <?php
                    /*
                     * Addressed by signal id so the recompute can write
                     * the new contribution straight into it. A `missing`
                     * row is not addressed: the instance not
                     * implementing a signal is not something editing a
                     * weight can change.
                     */
                    ?>
                    <?php
                    /*
                     * Which pair this cell's hue comes from. A row that
                     * reads the value is *with* or *against* the lean
                     * and keeps the red/green pair; a row that weighs
                     * the record is neither, and takes the value
                     * page's quieter carries/lacks ink
                     * (`value-palette.css`) — body ink where the
                     * record has something, muted where it does not.
                     *
                     * Without this the column said in colour what
                     * `review-2026-09-13.md` §D1 stopped it saying in
                     * words: *+28, four organisations reported it*
                     * rendered in the malicious red and *−7, no
                     * galaxy* in the benign green, which is the
                     * anchoring's claim about every row and is true of
                     * two. 09c-wiring.md §7.16 and §7.17 reasoned from
                     * `row = points × polarity`, so both predate the
                     * split.
                     */
                    $readsValue = false;
                    foreach ($item['badges'] as $badge) {
                        if ($badge['id'] === 'lean') {
                            $readsValue = true;
                            break;
                        }
                    }
                    ?>
                    <td class="r<?= $readsValue ? '' : ' is-weighs' ?>"<?=
                        $state === 'missing'
                        ? '' : ' data-ap-contrib="' . h($item['id']) . '"' ?>>
                        <?php if ($state === 'missing'): ?>
                            <span class="wb-sub"><?= h(__('not counted')) ?></span>
                        <?php elseif ($benchValue === null): ?>
                            <span class="wb-sub">&mdash;</span>
                        <?php elseif ($contribution === null): ?>
                            <div class="wb-sub"><?= h(__('did not fire')) ?></div>
                        <?php else: ?>
                            <?php
                            /*
                             * Which way this row pushed: `d-up` and
                             * `d-dn` resolve to `--vp-dir-with` /
                             * `--vp-dir-against`, which the cell
                             * above redirects to the carries/lacks
                             * pair on every row that weighs the
                             * record. Only the two that read the value
                             * keep the lean's red and green.
                             *
                             * This column used to take the directional
                             * pair for every row, matching the bench's
                             * delta beside it. The delta keeps it and
                             * should — *did this edit move the number*
                             * is a direction. A contribution is not,
                             * on nine rows out of eleven.
                             *
                             * The sign is printed as well as coloured.
                             * A hue is the fastest way to see it and the
                             * only way to miss it, and this column is
                             * read by people deciding whether a weight
                             * did what they meant.
                             */
                            ?>
                            <div class="num fw-bold <?= $contribution > 0
                                    ? 'd-up'
                                    : ($contribution < 0 ? 'd-dn' : 'd-0') ?>">
                                <?= h($contribution > 0
                                    ? '+' . $contribution
                                    : $contribution) ?>
                            </div>
                        <?php endif; ?>
                    </td>
                <?php endif; ?>
            </tr>
        <?php endforeach; ?>
    <?php endforeach; ?>
    </tbody>
</table>
