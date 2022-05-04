<div id="<?= h($node['module_data']['id']) ?>" class="sidebar-workflow-block" style="user-select: none; vertical-align: top;">
    <div style="display: flex;">
        <div class="icon" style="margin-right: 3px;">
            <i class="fa-fw <?= $this->FontAwesome->getClass($node['module_data']['icon']) ?>"></i>
        </div>
        <div>
            <strong style="font-size: larger; margin-right: 3px;"><?= h($node['module_data']['id']) ?></strong>
        </div>
    </div>
</div>