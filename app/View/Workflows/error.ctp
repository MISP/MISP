<?php
echo $this->element('/genericElements/SideMenu/side_menu', [
    'menuList' => 'workflows',
    'menuItem' => 'error',
]);
?>

<div class="index">
    <div class="alert alert-danger">
        <strong><?= __('Error while setting up Redis') ?></strong>
        <p>
            <?=__('Redis is essential for the Workflow system to run.') ?>
        </p>
        <?= __('Error:') ?>
        <pre><?= h($error) ?></pre>
    </div>
</div>