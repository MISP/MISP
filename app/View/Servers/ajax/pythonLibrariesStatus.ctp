<h3><?php echo __('Python libraries version');?>
    <it id="refreshPythonLibrariesStatus" class="fas fa-sync useCursorPointer" style="font-size: small; margin-left: 5px;" title="<?php echo __('Refresh python libraries version.'); ?>"></it>
</h3>
<?php if ($pythonLibraries['operational'] === -1): ?>
    <b class="red"><?= __('Could not run test script (stixtest.py). Please check error logs for more details.') ?></b>
<?php else: ?>

<b><?= __('Current libraries status') ?>:</b>
<?php if ($pythonLibraries['test_run'] === false): ?>
<b class="red bold"><?= __('Failed to run STIX diagnostics tool.') ?></b>
<?php elseif ($pythonLibraries['operational'] === 0): ?>
<b class="red bold"><?= __('Some of the libraries related to STIX are not installed. Make sure that all libraries listed below are correctly installed.') ?></b>
<?php elseif ($pythonLibraries['invalid_version']): ?>
<span class="orange"><?= __('Some versions should be updated.') ?></span>
<?php else: ?>
<b class="green"><?= __('OK') ?></b>
<?php endif ?>
<table class="table table-condensed table-bordered" style="width: 400px">
    <thead>
        <tr>
            <th><?= __('Library') ?></th>
            <th><?= __('Expected version') ?></th>
            <th><?= __('Installed version') ?></th>
            <th><?= __('Status') ?></th>
        </tr>
    </thead>
    <tbody>
        <?php foreach ($pythonLibraries as $name => $library): if (!isset($library['expected'])) continue; ?>
        <tr>
            <td><?= h($name) ?></td>
            <td><?= h($library['expected']) ?></td>
            <td><?= $library['version'] === 0 ? __('Not installed') : h($library['version']) ?></td>
            <td><?= $library['status'] ? '<i class="green fa fa-check" role="img" aria-label="' .  __('Correct') . '"></i>' : '<i class="red fa fa-times" role="img" aria-label="' .  __('Incorrect') . '"></i>' ?></td>
        </tr>
        <?php endforeach; ?>
    </tbody>
</table>
<?php endif; ?>