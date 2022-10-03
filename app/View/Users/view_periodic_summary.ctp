<div class="index">
    <div class="btn-group">
        <a class="btn <?= $period == 'daily' ? 'btn-primary' : 'btn-inverse' ?>" href="<?= $baseurl . '/users/viewPeriodicSummary/daily' ?>"><?= __('Daily') ?></a>
        <a class="btn <?= $period == 'weekly' ? 'btn-primary' : 'btn-inverse' ?>" href="<?= $baseurl . '/users/viewPeriodicSummary/weekly' ?>"><?= __('Weekly') ?></a>
        <a class="btn <?= $period == 'monthly' ? 'btn-primary' : 'btn-inverse' ?>" href="<?= $baseurl . '/users/viewPeriodicSummary/monthly' ?>"><?= __('Monthly') ?></a>
    </div>

    <h2><?= __('MISP %s summary', h($period)); ?></h2>

    <button type="button" class="btn btn-inverse" data-toggle="collapse" data-target="#summary-filters">
        <?= __('Show settings used to generate the summary') ?>
    </button>

    <div id="summary-filters" class="collapse">
        <pre>
<?= JsonTool::encode($periodic_settings, true) ?>
        </pre>
    </div>
    <div class="report-container" style="margin-top: 2em;">
        <?= $summary; ?>
    </div>
</div>

<?php
echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event-collection', 'menuItem' => 'viewPeriodicSummary'));
?>
