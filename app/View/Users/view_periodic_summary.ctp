<div class="index">
    <div class="btn-group">
        <a class="btn <?= $period === 'daily' ? 'btn-primary' : 'btn-inverse' ?>" href="<?= $baseurl . '/users/viewPeriodicSummary/daily' ?>"><?= __('Daily') ?></a>
        <a class="btn <?= $period === 'weekly' ? 'btn-primary' : 'btn-inverse' ?>" href="<?= $baseurl . '/users/viewPeriodicSummary/weekly' ?>"><?= __('Weekly') ?></a>
        <a class="btn <?= $period === 'monthly' ? 'btn-primary' : 'btn-inverse' ?>" href="<?= $baseurl . '/users/viewPeriodicSummary/monthly' ?>"><?= __('Monthly') ?></a>
    </div>
    <div class="input-append" style="margin-bottom: 0;">
        <input class="span2" id="btn-custom" type="number" min="1" step="1" placeholder="<?= __('Number of days from today') ?>">
        <a id="link-custom" class="btn <?= $period === 'custom' ? 'btn-primary' : 'btn-inverse' ?>" href="<?= $baseurl . '/users/viewPeriodicSummary/custom/lastdays:5' ?>"><?= __('Custom') ?></a>
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
        <?= $summary ?: __('No new events for this period'); ?>
    </div>
</div>
<?= $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event-collection', 'menuItem' => 'viewPeriodicSummary')); ?>


<script>
    var link = document.getElementById('link-custom');
    var input = document.getElementById('btn-custom');
    input.onchange = input.onkeyup = function() {
        var ressource = '<?= $baseurl ?>/users/viewPeriodicSummary/custom/lastdays:' + encodeURIComponent(this.value)
        link.setAttribute('href', ressource)
    };
</script>