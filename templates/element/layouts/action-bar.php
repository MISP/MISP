<?php

use Cake\Routing\Router;
?>

<div class="action-bar d-flex flex-nowrap flex-row mt-2 mb-1 rounded">
    <?php
        if (!empty($links)) {
            echo '<div>';
            foreach ($links as $i => $linkEntry) {
                if (empty($linkEntry['route_path'])) {
                    $active = false;
                } else {
                    $active = $linkEntry['route_path'] == $route_path;
                }
                if (!empty($linkEntry['url_vars'])) {
                    $linkEntry['url'] = $this->DataFromPath->buildStringFromDataPath($linkEntry['url'], $entity, $linkEntry['url_vars']);
                }
                if (!empty($linkEntry['selfLink'])) {
                    $url = Router::url(null);
                } else {
                    $url = Router::url($linkEntry['url']);
                }
                echo $this->Bootstrap->button([
                    'text' => h($linkEntry['label']),
                    'variant' => 'link',
                    'outline' => $active,
                    'size' => 'sm',
                    'class' => ['text-nowrap'],
                    'attrs' => [
                        'href' => $url,
                    ],
                ]);
            }
            echo '</div>';
        }

        if (!empty($actions)) {
            echo '<div class="ms-auto">';
            $badgeNumber = 0;
            foreach ($actions as $i => $actionEntry) {
                if (!empty($actionEntry['url_vars'])) {
                    $actionEntry['url'] = $this->DataFromPath->buildStringFromDataPath($actionEntry['url'], $entity, $actionEntry['url_vars']);
                }
                if (!empty($actionEntry['badge'])) {
                    $badgeNumber += 1;
                }
                $buttonBadge = !empty($actionEntry['badge']) ? $this->Bootstrap->badge($actionEntry['badge']) : '';
                echo $this->Bootstrap->button([
                    'text' => h($actionEntry['label']),
                    'icon' => h($actionEntry['icon']),
                    'variant' => $actionEntry['variant'] ?? 'primary',
                    'size' => 'sm',
                    'class' => ['text-nowrap'],
                    'onclick' => sprintf('UI.overlayUntilResolve(this, UI.submissionModalAutoGuess(\'%s\'))', h(Router::url($actionEntry['url']))),
                ], $buttonBadge);
            }
            echo '</div>';
        }
    ?>
</div>

<!-- 
<div class="breadcrumb-link-container position-absolute end-0 d-flex">
    <div class="header-breadcrumb-children d-none d-md-flex btn-group">
        <?= $breadcrumbLinks ?>
        <?php if (!empty($breadcrumbAction)) : ?>
            <a class="btn btn-primary btn-sm dropdown-toggle" href="#" role="button" id="dropdownMenuBreadcrumbAction" data-bs-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                <?= __('Actions') ?>
                <?=
                $badgeNumber == 0 ? '' : $this->Bootstrap->badge([
                    'text' => h($badgeNumber),
                    'variant' => 'warning',
                    'pill' => false,
                    'title' => __n('There is {0} action available', 'There are {0} actions available', $badgeNumber, h($badgeNumber)),
                ])
                ?>
            </a>
            <div class="dropdown-menu dropdown-menu-end" aria-labelledby="dropdownMenuBreadcrumbAction">
                <?= $breadcrumbAction ?>
            </div>
        <?php endif; ?>
    </div>
</div> -->