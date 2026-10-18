<?php
/**
 * Statistics sightings tab: the top sources of the user's organisation's sightings.
 *
 * $toplist source => sightings, busiest first
 * $data    source => type (sighting, false-positive, expiration) => sightings
 */
$types = [
    'sighting' => __('Sighting'),
    'false-positive' => __('False positive'),
    'expiration' => __('Expiration'),
];
?>
<div class="card shadow-sm mb-3">
    <div class="card-header fw-semibold"><?= __('Top sources of your organisation\'s sightings') ?></div>
    <div class="table-responsive">
        <table class="table table-sm table-hover align-middle mb-0">
            <thead>
                <tr>
                    <th><?= __('Source') ?></th>
                    <th class="text-end"><?= __('Sightings') ?></th>
                    <?php foreach ($types as $label): ?>
                    <th class="text-end"><?= h($label) ?></th>
                    <?php endforeach; ?>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($toplist)): ?>
                <tr><td colspan="5" class="text-center text-body-secondary py-4"><?= __('Your organisation has no sightings.') ?></td></tr>
                <?php endif; ?>
                <?php foreach (array_slice($toplist, 0, 10, true) as $source => $total): ?>
                <tr>
                    <td><?= h($source) ?></td>
                    <td class="text-end fw-semibold"><?= number_format((int)$total) ?></td>
                    <?php foreach (array_keys($types) as $type): ?>
                    <td class="text-end <?= empty($data[$source][$type]) ? 'text-body-secondary' : '' ?>"><?= number_format((int)($data[$source][$type] ?? 0)) ?></td>
                    <?php endforeach; ?>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>
