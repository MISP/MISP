<?php
/**
 * Statistics organisations tab.
 *
 * $orgs  name => organisation with userCount, eventCount, attributeCount and
 *        orgActivity (User::getOrgActivity() over a year), the counts absent at 0
 * $scope local, external or all
 */
$scopes = [
    'local' => __('Local'),
    'external' => __('Known remote'),
    'all' => __('All'),
];
$sparkline = function (array $activity) {
    $start = strtotime('-364 days');
    $weeks = array_fill(0, 53, 0);
    foreach ($activity as $date => $count) {
        $week = intdiv(strtotime($date) - $start, 7 * 86400);
        if ($week >= 0 && $week < 53) {
            $weeks[$week] += (int)$count;
        }
    }
    $max = max($weeks);
    if ($max === 0) {
        return '<span class="text-body-secondary">—</span>';
    }
    $points = [];
    foreach ($weeks as $i => $count) {
        $points[] = sprintf('%.1f,%.1f', $i * 120 / 52, 22 - 20 * $count / $max);
    }
    return sprintf(
        '<svg width="120" height="24" viewBox="0 0 120 24" class="text-info" role="img" aria-label="%s"><polyline points="%s" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/></svg>',
        h(__('Attributes in the events created per week')),
        implode(' ', $points)
    );
};
$cardId = 'stats-orgs-' . mt_rand();
?>
<div class="card shadow-sm mb-3" id="<?= h($cardId) ?>">
    <div class="card-header d-flex align-items-center gap-3">
        <span class="fw-semibold"><?= __('Organisations') ?></span>
        <div class="btn-group btn-group-sm ms-auto" role="group" aria-label="<?= h(__('Organisations shown')) ?>">
            <?php foreach ($scopes as $key => $label): ?>
            <button type="button" class="btn <?= $key === $scope ? 'btn-primary' : 'btn-outline-secondary' ?>"
                    data-stats-url="<?= h($baseurl . '/users/statistics/orgs/scope:' . $key) ?>"><?= h($label) ?></button>
            <?php endforeach; ?>
        </div>
    </div>
    <div class="table-responsive">
        <table class="table table-sm table-hover align-middle mb-0">
            <thead>
                <tr>
                    <th><?= __('Organisation') ?></th>
                    <th class="text-end"><?= __('Users') ?></th>
                    <th class="text-end"><?= __('Events') ?></th>
                    <th class="text-end"><?= __('Attributes') ?></th>
                    <th><?= __('Nationality') ?></th>
                    <th><?= __('Type') ?></th>
                    <th><?= __('Sector') ?></th>
                    <th title="<?= h(__('Attributes in the events the organisation created, per week')) ?>"><?= __('Activity (1 year)') ?></th>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($orgs)): ?>
                <tr><td colspan="8" class="text-center text-body-secondary py-4"><?= __('No organisations') ?></td></tr>
                <?php endif; ?>
                <?php foreach ($orgs as $org): ?>
                <tr>
                    <td>
                        <a class="d-inline-flex align-items-center gap-2 text-decoration-none" href="<?= h($baseurl . '/organisations/view/' . (int)$org['id']) ?>">
                            <span class="d-inline-flex justify-content-center flex-shrink-0" style="width: 24px;"><?= $this->OrgImg->getOrgLogoV2($org, 24, false) ?></span>
                            <span><?= h($org['name']) ?></span>
                        </a>
                    </td>
                    <?php foreach (['userCount', 'eventCount', 'attributeCount'] as $field): ?>
                    <td class="text-end <?= empty($org[$field]) ? 'text-body-secondary' : 'fw-semibold' ?>"><?= number_format((int)($org[$field] ?? 0)) ?></td>
                    <?php endforeach; ?>
                    <td><?= isset($org['nationality']) && $org['nationality'] !== 'Not specified' ? h($org['nationality']) : '' ?></td>
                    <td><?= h($org['type'] ?? '') ?></td>
                    <td><?= h($org['sector'] ?? '') ?></td>
                    <td><?= $sparkline($org['orgActivity']['data'] ?? []) ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>
<script>
(function () {
    var card = document.getElementById(<?= json_encode($cardId) ?>);
    card.querySelectorAll('[data-stats-url]').forEach(function (button) {
        button.addEventListener('click', function () {
            reloadAjaxTabIndex(card.closest('.ajax-tab-content'), button.dataset.statsUrl);
        });
    });
})();
</script>
