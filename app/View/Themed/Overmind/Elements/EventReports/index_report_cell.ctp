<?php
/**
 * A report in the reports indexes' table: its distribution, then its name over
 * the opening of its text.
 *
 * Parameters:
 *   row  array  one row of the index, with the `ctx` Elements/EventReports/index
 *               gives it
 *
 * Read from the view: $baseurl.
 */
$report = $row['EventReport'];
$excerpt = $row['ctx']['digest']['excerpt'];
$dist = $this->DistributionLevel->get((int)($report['distribution'] ?? 0));
$distTitle = __('Distribution: %s', $dist['label'])
    . (empty($row['SharingGroup']['name']) ? '' : ' (' . $row['SharingGroup']['name'] . ')');
?>
<div class="er-report">
    <span class="ov-obj-dist"
          style="--ov-dist-bg:<?= h($this->DistributionLevel->themed($dist, 'bg')) ?>;--ov-dist-ink:<?= h($this->DistributionLevel->themed($dist, 'fg')) ?>;"
          title="<?= h($distTitle) ?>">
        <i class="<?= h($dist['icon']) ?>"></i>
    </span>
    <div class="er-report-title">
        <div class="er-report-name">
            <?= $this->element('genericElementsBS5/IndexTable/Fields/report_value', [
                'row' => $row,
                'field' => ['data_path' => 'EventReport.name', 'reader' => $row['ctx']['reader']],
                'viewMode' => 'card',
                'viewUrl' => $baseurl . '/event_reports/view/' . (int)$report['id'],
            ]) ?>
            <?php if (!empty($report['deleted'])): ?>
                <span class="ov-obj-deleted"><i class="fas fa-trash"></i><?= __('Deleted') ?></span>
            <?php endif; ?>
        </div>
        <?php if ($excerpt === ''): ?>
            <div class="er-report-excerpt is-empty"><?= __('No content yet') ?></div>
        <?php else: ?>
            <div class="er-report-excerpt" title="<?= h($excerpt) ?>"><?= h($excerpt) ?></div>
        <?php endif; ?>
    </div>
</div>
