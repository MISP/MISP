<?php
$name = Hash::get($row, $field['data_path']);

if (empty($name)) {
    return;
}

$isCard = isset($viewMode) && $viewMode === 'card';
// On the event page the name opens the report reader in place.
$reader = !empty($field['reader']);
?>

<div class="d-flex align-items-baseline gap-2 mb-0">
    <?php if (!$isCard):
        echo $this->element(
            '/genericElementsBS5/IndexTable/Fields/distribution',
            [
                'row' => $row,
                'field' => [
                    'data_path' => 'EventReport.distribution',
                    'display' => 'short'
                ]
            ]
        );
    endif; ?>
    <?php if ($reader): ?>
        <a class="mb-0 fw-semibold text-reset text-decoration-none eo-report-link"
           href="<?= h($baseurl . '/eventReports/view/' . (int)Hash::get($row, 'EventReport.id')) ?>"
           title="<?= h(__('Read this report')) ?>"
           data-report-read="<?= (int)Hash::get($row, 'EventReport.id') ?>"
           data-report-name="<?= h($name) ?>"
           data-report-sub="<?= h($this->element('Events/View/report_meta', [
               'event_id' => Hash::get($row, 'EventReport.event_id'),
               'org' => Hash::get($row, 'Event.Orgc.name') ?? '',
               'timestamp' => Hash::get($row, 'EventReport.timestamp'),
           ])) ?>">
            <?= h($name) ?>
        </a>
    <?php else: ?>
        <p class="mb-0 fw-semibold">
            <?= h($name) ?>
        </p>
    <?php endif; ?>
</div>
