<?php
/**
 * Who put this value on the instance, and when.
 *
 *   - **When**: the first and the last report and who made them, the
 *     busiest month, and a bar a month over the value's whole life. The
 *     silent months are drawn, because the run is the reading.
 *   - **Who**: occurrences per organisation, how many of them each flagged
 *     for IDS, and the months it reported the value in. The organisations
 *     are the Assessment tab's *Who says what*, read the same way.
 *
 * Soft-deleted occurrences are not counted, so the total can be below the
 * fact strip's.
 *
 * Lazily loaded into `.ajax-card` from ValuesController::viewReporting.
 *
 * @var array $valueIntelligence
 * @var string $valueB64
 */
$reporting = $valueIntelligence['reporting'];
$months = $reporting['months'];
$orgs = $reporting['orgs'];
$first = $reporting['first'] ?? null;
$last = $reporting['last'] ?? null;
$hidden = $reporting['orgs_total'] - count($orgs);
$topOrg = empty($orgs) ? 0 : $orgs[0]['occurrences'];

$monthLabel = function ($key, $format = 'M Y') {
    return date($format, strtotime($key . '-01'));
};
$dayLabel = function ($ts) {
    return date('j M Y', (int)$ts);
};
$period = function (array $org) {
    if ($org['oldest'] === null && $org['newest'] === null) {
        return '—';
    }
    $from = date('M Y', (int)($org['oldest'] ?? $org['newest']));
    $to = date('M Y', (int)($org['newest'] ?? $org['oldest']));
    return $from === $to ? $from : $from . ' – ' . $to;
};

$peak = empty($months) ? 0 : max($months);
$peakMonth = $peak > 0 ? array_search($peak, $months, true) : null;
$active = count(array_filter($months));
$monthKeys = array_keys($months);
// Up to a year and a half, every month is named; past it, the years only.
$monthly = count($months) <= 18;
// Counts over the bars while they have the room, otherwise over the peak alone.
$countAll = count($months) <= 24;

$clauses = array();
if (!empty($orgs)) {
    $clauses[] = h(sprintf(
        __n('%s occurrence', '%s occurrences', $reporting['occurrences']),
        number_format($reporting['occurrences'])
    )) . ' ' . h(sprintf(
        __n('from %s organisation', 'from %s organisations', $reporting['orgs_total']),
        number_format($reporting['orgs_total'])
    ));
}
if (!empty($months)) {
    $clauses[] = h(sprintf(
        __n('reported in %1$s of %2$s month', 'reported in %1$s of %2$s months', count($months)),
        number_format($active),
        number_format(count($months))
    ));
}
$subtitle = empty($clauses)
    ? h(__('Nothing dated to report'))
    : '<span title="' . h(__('Soft-deleted occurrences are not counted.')) . '">'
        . implode(' &nbsp;·&nbsp; ', $clauses) . '</span>';

$orgLink = function (array $org) {
    return $this->element('Values/View/value_org_link', array('org' => $org));
};
?>
<div class="card shadow-sm mb-3 vp-panel"
     style="--vp-panel-color: var(--object);">

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('Reporting'),
        'panelIcon' => 'misp-icon misp-icon-organisation misp-simple',
        'panelColor' => 'var(--object)',
        'panelSub' => $subtitle,
    )) ?>

    <?php if (empty($orgs) && empty($months)): ?>
        <?php // Absent and hidden are different answers; only one is knowable here. ?>
        <div class="vp-empty">
            <span class="misp-icon misp-icon-organisation misp-simple"></span>
            <span><?= __('No event you can see carries this value.') ?></span>
        </div>
    <?php else: ?>
        <div class="p-3 vp-rep-wrap">
        <div class="vp-rep">

            <section class="vp-rep-when" aria-label="<?= h(__('When it was reported')) ?>">
                <div class="vp-subhead"><?= __('When') ?></div>
                <div class="vp-rep-facts">
                    <?php if ($first !== null): ?>
                        <div class="vp-rep-fact">
                            <small><?= __('First reported') ?></small>
                            <b><?= h($dayLabel($first['at'])) ?></b>
                            <span><?= h(sprintf(__('by %s'), $first['org']['name'])) ?></span>
                        </div>
                    <?php endif; ?>
                    <?php if ($last !== null): ?>
                        <div class="vp-rep-fact">
                            <small><?= __('Last reported') ?></small>
                            <b><?= h($dayLabel($last['at'])) ?></b>
                            <span><?= h(sprintf(__('by %s'), $last['org']['name'])) ?></span>
                        </div>
                    <?php endif; ?>
                    <?php if ($peakMonth !== null): ?>
                        <div class="vp-rep-fact">
                            <small><?= __('Busiest month') ?></small>
                            <b><?= h($monthLabel($peakMonth)) ?></b>
                            <span><?= h(sprintf(
                                __n('%s occurrence', '%s occurrences', $peak),
                                number_format($peak)
                            )) ?></span>
                        </div>
                    <?php endif; ?>
                </div>

                <?php if (empty($months)): ?>
                    <div class="vp-empty vp-empty-inline">
                        <i class="fas fa-clock"></i>
                        <span><?= __('No occurrence carries a date.') ?></span>
                    </div>
                <?php else: ?>
                    <div class="vp-rep-chart<?= count($months) > 36 ? ' is-dense' : '' ?>" role="img"
                         aria-label="<?= h(__('Occurrences by month, oldest first')) ?>">
                        <?php foreach ($months as $month => $count): ?>
                            <span class="vp-rep-col<?= $count === 0 ? ' is-zero' : '' ?><?= $month === $peakMonth ? ' is-peak' : '' ?>"
                                  title="<?= h(sprintf(
                                      __n('%2$s — %1$s occurrence', '%2$s — %1$s occurrences', $count),
                                      number_format($count),
                                      $monthLabel($month)
                                  )) ?>">
                                <?php if ($count > 0 && ($countAll || $month === $peakMonth)): ?>
                                    <span class="vp-rep-n"><?= h(number_format($count)) ?></span>
                                <?php endif; ?>
                                <span class="vp-rep-bar"
                                      style="--h: <?= $peak > 0 ? round(100 * $count / $peak) : 0 ?>%;"></span>
                            </span>
                        <?php endforeach; ?>
                    </div>
                    <div class="vp-rep-axis<?= count($months) > 36 ? ' is-dense' : '' ?><?= $monthly ? '' : ' is-years' ?>" aria-hidden="true">
                        <?php foreach ($monthKeys as $index => $month): ?>
                            <?php
                            $january = substr($month, -2) === '01';
                            $year = ($index === 0 || $january) ? substr($month, 0, 4) : null;
                            ?>
                            <span class="vp-rep-tick<?= $year !== null ? ' is-year' : '' ?>">
                                <?php if ($monthly): ?>
                                    <span><?= h($monthLabel($month, 'M')) ?></span>
                                <?php endif; ?>
                                <?php if ($year !== null && ($monthly || $january)): ?>
                                    <small><?= h($year) ?></small>
                                <?php endif; ?>
                            </span>
                        <?php endforeach; ?>
                    </div>
                    <?php if (!$monthly): ?>
                        <div class="vp-rep-ends" aria-hidden="true">
                            <span><?= h($monthLabel(reset($monthKeys))) ?></span>
                            <span><?= h($monthLabel(end($monthKeys))) ?></span>
                        </div>
                    <?php endif; ?>
                <?php endif; ?>
            </section>

            <section class="vp-rep-who" aria-label="<?= h(__('Who reported it')) ?>">
                <div class="vp-subhead"><?= __('Reported by') ?></div>
                <?php if (empty($orgs)): ?>
                    <div class="vp-empty vp-empty-inline">
                        <span class="misp-icon misp-icon-organisation misp-simple"></span>
                        <span><?= __('Every occurrence is soft-deleted.') ?></span>
                    </div>
                <?php else: ?>
                    <table class="table align-middle mb-0 ix-table vp-rep-table">
                        <thead>
                            <tr>
                                <th scope="col"><?= __('Organisation') ?></th>
                                <th scope="col"><?= __('Occurrences') ?></th>
                                <th scope="col" class="text-center" title="<?= h(__('Occurrences flagged for IDS')) ?>">
                                    <i class="fas fa-shield-halved" aria-hidden="true"></i>
                                    <span class="visually-hidden"><?= __('IDS') ?></span>
                                </th>
                                <th scope="col"><?= __('Period') ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($orgs as $org): ?>
                                <tr>
                                    <td class="vp-rep-org">
                                        <?= $orgLink($org) ?>
                                        <?php if ($first !== null && (int)$first['org']['id'] === (int)$org['id']): ?>
                                            <span class="vp-rep-first" title="<?= h(__('The first organisation to report this value')) ?>"><?= __('first') ?></span>
                                        <?php endif; ?>
                                    </td>
                                    <td class="vp-rep-occ">
                                        <span class="vp-rep-track" aria-hidden="true">
                                            <span style="width: <?= $topOrg > 0 ? round(100 * $org['occurrences'] / $topOrg) : 0 ?>%;"></span>
                                        </span>
                                        <b><?= h(number_format($org['occurrences'])) ?></b>
                                    </td>
                                    <td class="vp-rep-ids text-center"
                                        title="<?= h(sprintf(
                                            __n('%1$s of its %2$s occurrence is flagged for IDS',
                                                '%1$s of its %2$s occurrences are flagged for IDS',
                                                $org['occurrences']),
                                            number_format($org['ids']),
                                            number_format($org['occurrences'])
                                        )) ?>">
                                        <i class="fas fa-shield-halved om-flag <?= $org['ids'] > 0 ? 'text-warning' : 'text-secondary' ?>" aria-hidden="true"></i>
                                        <span><?= h($org['ids']) ?>/<?= h($org['occurrences']) ?></span>
                                    </td>
                                    <td class="vp-rep-period"><?= h($period($org)) ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                    <?php if ($hidden > 0): ?>
                        <div class="vp-rep-rest">
                            <?= h(sprintf(
                                __n('%s further organisation', '%s further organisations', $hidden),
                                number_format($hidden)
                            )) ?> &nbsp;·&nbsp;
                            <a href="#tab-occurrences"><?= __('See the Occurrences tab') ?></a>
                        </div>
                    <?php endif; ?>
                <?php endif; ?>
            </section>

        </div>
        </div>
    <?php endif; ?>

</div>
