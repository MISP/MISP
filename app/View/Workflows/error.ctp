<?php
echo $this->element('/genericElements/SideMenu/side_menu', [
    'menuList' => 'workflows',
    'menuItem' => 'error',
]);
?>

<div class="index">
    <div class="alert alert-danger">
        <strong><?= __('Could not access Workflow system') ?></strong>
        <p>
            <?=__('Some components are essential for the Workflow system to run.') ?>
        </p>
        <?= __n('Error:', 'Errors:', count($requirementErrors)) ?>
        <ul>
            <?php foreach ($requirementErrors as $error): ?>
                <li><?= h($error) ?></li>
            <?php endforeach; ?>
        </ul>
    </div>
</div>
