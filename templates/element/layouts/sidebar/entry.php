<?php
    $seed = 'sb-' . mt_rand();
    $icon = $parent['icon'] ?? '';
    $label = $parent['label'] ?? '';
    $children = $parent['children'] ?? [];
    $active = false;

    if (!empty($children)) {
        $url = "#{$seed}";
    } else {
        $url = $parent['url'] ?? false;
    }

    $controller = \Cake\Utility\Inflector::variable($this->request->getParam('controller'));
    $action = \Cake\Utility\Inflector::variable($this->request->getParam('action'));
    $currentURL = "/{$controller}/{$action}";
    if ($url == $currentURL) {
        $active = true;
    }

    $hasActiveChild = false;
    if (!empty($children)) {
        $flattened = Cake\Utility\Hash::flatten($children);
        $flattenedValues = array_values($flattened);
        if (in_array($currentURL, $flattenedValues)) {
            $hasActiveChild = true;
        }
    }

    $severity = [
        'primary' => -1,
        'info' => 0,
        'warning' => 1,
        'danger' => 2,
    ];

    $hasNotification = false;
    $childHasNotification = false;
    $maxSeverity = -1;
    $childMaxSeverity = -1;
    $notificationAmount = 0;
    foreach ($children as $childName => $child) { // children notification
        foreach ($notifications as $notification) {
            if (!empty($notification['_sidebarId']) && $notification['_sidebarId'] == $childName) {
                $childHasNotification = true;
                $childMaxSeverity = max($childMaxSeverity, $severity[$notification['variant']] ?? 0);
            }
        }
    }
    foreach ($notifications as $notification) { // leaf notification
        if (!empty($notification['_sidebarId']) && $notification['_sidebarId'] == $parentName) {
            $hasNotification = true;
            $maxSeverity = max($maxSeverity, $severity[$notification['variant']] ?? 0);
            $notificationAmount += 1;
        }
    }
    $notificationVariant = array_flip($severity)[$maxSeverity];
    $childNotificationVariant = array_flip($severity)[$childMaxSeverity];
?>

<li class="sidebar-link-container <?= !empty($children) ? 'parent' : '' ?>">
    <?php if (!empty($children) || !empty($url)): ?>
        <a
            class="d-flex align-items-center sidebar-link <?= (!empty($children) && !$hasActiveChild) ? 'collapsed' : '' ?> <?= $active ? 'active' : '' ?> <?= $hasActiveChild ? 'have-active-child' : '' ?>"
            href="<?= h($url) ?>"
            <?= $hasActiveChild ? 'aria-expanded="true"' : '' ?>
        >
        <?php if (is_array($icon)):?>
            <i class="position-relative sidebar-icon">
                <?php if (!empty($icon['stacked'])):?>
                    <?=
                        sprintf('<span class="fa-stack fa-stack-small stacked-sidebar-icon">%s%s</span>',
                            $this->Bootstrap->node('span', [
                                'class' => sprintf('fas fa-stack-2x fa-%s %s', h($icon['stacked'][0]['icon'] ?? ''), h($icon['stacked'][0]['class'] ?? '')),
                                'style' => h($icon['stacked'][0]['style'] ?? ''),
                            ]),
                            $this->Bootstrap->node('span', [
                                'class' => sprintf('fas fa-stack-1x fa-%s %s', h($icon['stacked'][1]['icon'] ?? ''), h($icon['stacked'][1]['class'] ?? '')),
                                'style' => h($icon['stacked'][1]['style'] ?? ''),
                            ]),
                        )
                    ?>
                <?php else: ?>
                    <?= $icon['html'] ?? '' ?>
                <?php endif; ?>
        <?php else:?>
            <i class="position-relative sidebar-icon <?= $this->FontAwesome->getClass($icon) ?>">
        <?php endif;?>
                <?php
                if ($childHasNotification || ($hasNotification && !empty($children))) {
                    echo $this->Bootstrap->notificationBubble([
                        'variant' => $childHasNotification ? $childNotificationVariant : $notificationVariant,
                        'borderVariant' => 'light',
                    ]);
                }
                ?>
            </i>
            <span class="text"><?= h($label) ?></span>
                <?php
                if (empty($children) && $hasNotification) {
                    echo $this->Bootstrap->badge([
                        'text' => $notificationAmount,
                        'class' => 'ms-auto',
                        'variant' => $notificationVariant,
                    ]);
                }
                ?>
        </a>
        <?php if (!empty($children)): ?>
            <?= $this->element('layouts/sidebar/sub-menu', [
                    'submenuName' => $label,
                    'seed' => $seed,
                    'children' => $children,
                    'open' => $hasActiveChild,
                ]);
            ?>
        <?php endif; ?>
    <?php endif; ?>
</li>
