<?php
/**
 * Who says what — the same argument counted by organisation rather
 * than by signal.
 *
 * Every verdict layout ends with this card, because consensus is itself
 * a signal and a reader who distrusts one source needs to see the
 * verdict with that source taken out.
 *
 * The first five columns are the same question everywhere: how much
 * each organisation contributed and what it thinks. What differs is
 * what the layout needs after them, so the trailing columns are named
 * by the caller.
 *
 * @var array $verdict
 * @var array $orgColumns  Any of `to_ids`, `reliability`
 * @var string $orgsSub    The subtitle: why this table is here for
 *                         this particular value
 * @var array|null $orgGrading OrgGradeTool::reading()
 */
App::uses('ValueTrustTool', 'Tools/ValueIntelligence');

$orgs = $verdict['orgs'] ?? array();
$orgColumns = $orgColumns ?? array('to_ids', 'reliability');

$headings = array(
    'to_ids' => __('to_ids stance'),
    'reliability' => __('Source reliability'),
);
?>
<?php if (!empty($orgs)): ?>
    <div class="card shadow-sm mb-3 vp-panel"
         style="--vp-panel-color: var(--object);">

        <?= $this->element('Values/View/value_panel_header', array(
            'panelTitle' => __('Who says what'),
            'panelIcon' => 'misp-icon misp-icon-organisation misp-simple',
            'panelColor' => 'var(--object)',
            'panelSub' => h($orgsSub),
        )) ?>

        <div class="table-responsive">
            <table class="table table-sm align-middle vp-table mb-0">
                <thead>
                    <tr>
                        <th><?= __('Organisation') ?></th>
                        <th class="text-end"><?= __('Occurrences') ?></th>
                        <th class="text-end"><?= __('Sightings') ?></th>
                        <?php /*
                         * The last of the three counts, and the one
                         * that sits against a column of words. Flush
                         * right it read as part of them — *0 none
                         * stated* on every row where nobody has
                         * stated an opinion.
                         */ ?>
                        <th class="text-end vp-orgs-count-last">
                            <?= __('False positives') ?>
                        </th>
                        <th><?= __('Opinion') ?></th>
                        <?php foreach ($orgColumns as $column): ?>
                            <th><?= h($headings[$column] ?? $column) ?></th>
                        <?php endforeach; ?>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($orgs as $org): ?>
                        <tr>
                            <td class="fw-semibold">
                                <span class="vp-org">
                                    <?= $this->EventIndex->orgTile(array(
                                        'id' => $org['org_id'] ?? null,
                                        'uuid' => $org['org_uuid'] ?? null,
                                        'name' => $org['org'],
                                    ), 20) ?>
                                    <span><?= h($org['org']) ?></span>
                                </span>
                            </td>
                            <td class="text-end">
                                <?= h($org['occurrences']) ?>
                            </td>
                            <td class="text-end">
                                <?= h($org['sightings']) ?>
                            </td>
                            <td class="text-end vp-orgs-count-last<?=
                                $org['fp'] > 0
                                ? ' text-danger fw-semibold'
                                : ' text-muted' ?>">
                                <?= h($org['fp']) ?>
                            </td>
                            <td>
                                <?php if ($org['opinion'] === null): ?>
                                    <span class="text-muted">
                                        <?= __('none stated') ?>
                                    </span>
                                <?php else: ?>
                                    <span class="vp-opinion"
                                          title="<?= h(sprintf(
                                              __('Opinion %s of 100'),
                                              $org['opinion']
                                          )) ?>">
                                        <span class="vp-opinion-track">
                                            <span class="vp-opinion-fill"
                                                  style="width: <?=
                                                      (int)$org['opinion']
                                                      ?>%;"></span>
                                        </span>
                                        <span class="vp-opinion-value">
                                            <?= h($org['opinion']) ?>
                                        </span>
                                    </span>
                                <?php endif; ?>
                            </td>

                            <?php foreach ($orgColumns as $column): ?>
                                <?php if ($column === 'reliability'): ?>
                                    <?php
                                    /*
                                     * The chip is a 22px square, because
                                     * the vocabulary it was drawn for is
                                     * one character: the admiralty
                                     * grades `A` to `G`. The seventh
                                     * member of that vocabulary is the
                                     * word `unrated`, which overflowed
                                     * its own box on every row of every
                                     * value on this instance — nothing
                                     * here is graded yet.
                                     *
                                     * Not a wider chip. A grade is
                                     * something an analyst put there and
                                     * the chip is what says so; `unrated`
                                     * is its absence, and this card draws
                                     * absences as absences everywhere
                                     * else — the hollow bar in the
                                     * ledger, *none stated* in the
                                     * column to the left of this one.
                                     */
                                    ?>
                                    <?php
                                    $gradeBadge = $this->OrgGrade->badge(
                                        array(
                                            'id' => $org['org_id'] ?? 0,
                                            'uuid' => $org['org_uuid'] ?? '',
                                            'name' => $org['org'],
                                        ),
                                        $orgGrading ?? null,
                                        'square'
                                    );
                                    ?>
                                    <td>
                                        <?php if ($gradeBadge !== ''): ?>
                                            <span class="vp-grade">
                                                <?= $gradeBadge ?>
                                                <span class="text-muted vp-grade-none">
                                                    <?= h(__('unrated')) ?>
                                                </span>
                                            </span>
                                        <?php elseif ($org['reliability']
                                            === ValueTrustTool::UNRATED
                                        ): ?>
                                            <span class="text-muted">
                                                <?= h(__('unrated')) ?>
                                            </span>
                                        <?php else: ?>
                                            <span class="vp-reliability"
                                                  title="<?= h(sprintf(
                                                      __('Source'
                                                      . ' reliability %s'),
                                                      $org['reliability']
                                                  )) ?>">
                                                <?= h($org['reliability']) ?>
                                            </span>
                                        <?php endif; ?>
                                    </td>
                                <?php else: ?>
                                    <td><?= h($org[$column]) ?></td>
                                <?php endif; ?>
                            <?php endforeach; ?>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>

    </div>
<?php endif; ?>
