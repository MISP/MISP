<?php
$classFromSeverity = [
    'info' => 'info',
    'warning' => 'warning',
    'error' => 'danger',
];
?>
<div id="<?= h($block['id']) ?>" class="sidebar-workflow-block block-type-<?= h($block['module_type'] ?? 'action') ?>" style="user-select: none;" data-blockid="<?= h($block['id']) ?>" title="<?= !empty($block['disabled']) ? __('This module is disabled') : '' ?>" data-block-disabled="<?= !empty($block['disabled']) ? '1' : '0' ?>" data-is-misp-module="<?= !empty($block['is_misp_module']) ?>">
    <div class="icon">
        <?php if (!empty($block['icon'])) : ?>
            <i class="<?= $this->FontAwesome->getClass($block['icon']) ?> fa-fw <?= $block['icon_class'] ?? '' ?>"></i>
        <?php elseif (!empty($block['icon_path'])) : ?>
            <img src="<?= sprintf('%s/%s/%s', $baseurl, 'img', h($block['icon_path'])) ?>" alt="Icon of <?= h($block['name']) ?>" style="width: 18px; filter: grayscale(1);">
        <?php endif; ?>
    </div>
    <div>
        <div style="display: flex;">
            <strong style="font-size: large;">
                <?= h($block['name']) ?>
            </strong>
            <small style="margin-left: 2px;">v<?= h($block['version']) ?></small>
            <span style="margin-left: 2px;" class="text-error">
                <?php if (!empty($block['blocking'])) : ?>
                    <i title="<?= __('This module can block execution') ?>" class="fa-lg fa-fw <?= $this->FontAwesome->getClass('stop-circle') ?>"></i>
                <?php endif; ?>
            </span>
            <span class="block-notification-container">
                <?php foreach (array_keys($classFromSeverity) as $severity) : ?>
                    <?php
                    $visibleNotifications = array_filter($block['notifications'][$severity], function ($notification) {
                        return !empty($notification['__show_in_sidebar']);
                    });
                    ?>
                    <?php if (!empty($visibleNotifications)) : ?>
                        <button class="btn btn-mini btn-<?= $classFromSeverity[$severity] ?>" type="button" title="<?= implode('&#013;', h(Hash::extract($visibleNotifications, '{n}.text'))) ?>" onclick="showNotificationModalForSidebarModule(this)">
                            <?php if ($severity == 'danger') : ?>
                                <i class="<?= $this->FontAwesome->getClass('times-circle') ?>"></i>
                            <?php elseif ($severity == 'warning') : ?>
                                <i class="<?= $this->FontAwesome->getClass('exclamation-triangle') ?>"></i>
                            <?php else : ?>
                                <i class="<?= $this->FontAwesome->getClass('exclamation-circle') ?>"></i>
                            <?php endif; ?>
                            <strong>
                                <?= count($visibleNotifications) ?>
                            </strong>
                        </button>
                    <?php endif; ?>
                <?php endforeach; ?>
            </span>
        </div>
        <div class="muted"><?= h($block['description']) ?></div>
    </div>
    <?php if ($block['is_misp_module']) : ?>
        <span class="misp-module-background">
        </span>
    <?php endif; ?>
</div>