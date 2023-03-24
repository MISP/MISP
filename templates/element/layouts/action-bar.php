<?php

use Cake\Routing\Router;
?>

<div class="action-bar d-flex flex-nowrap flex-row mt-2 mb-1 rounded">
    <?php
        if (!empty($actions)) {
            echo '<div>';
            $badgeNumber = 0;
            foreach ($actions as $i => $actionEntry) {
                if (!empty($actionEntry['url_vars'])) {
                    $actionEntry['url'] = $this->DataFromPath->buildStringFromDataPath($actionEntry['url'], $entity, $actionEntry['url_vars']);
                }
                if (!empty($actionEntry['badge'])) {
                    $badgeNumber += 1;
                }
                if (!empty($actionEntry['isPOST'])) {
                    $onclickFunction = sprintf('UI.overlayUntilResolve(this, UI.submissionModalAutoGuess(\'%s\'))', h(Router::url($actionEntry['url'])));
                } else if (!empty($actionEntry['isRedirect'])) {
                    $onclickFunction = sprintf('window.location.replace(\'%s\');', h(Router::url($actionEntry['url'])));
                } else {
                    $onclickFunction = sprintf('UI.overlayUntilResolve(this, UI.modalFromUrl(\'%s\'))', h(Router::url($actionEntry['url'])));
                }
                $buttonBadge = !empty($actionEntry['badge']) ? $this->Bootstrap->badge($actionEntry['badge']) : '';
                echo $this->Bootstrap->button([
                    'text' => h($actionEntry['label']),
                    'icon' => h($actionEntry['icon']),
                    'variant' => $actionEntry['variant'] ?? 'primary',
                    'class' => ['text-nowrap'],
                    'onclick' => $onclickFunction,
                ], $buttonBadge);
            }
            echo '</div>';
        }

        if (!empty($links)) {
            echo '<div class="ms-auto">';
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
                    'nodeType' => 'a',
                    'text' => h($linkEntry['label']),
                    'variant' => 'link',
                    'outline' => $active,
                    'class' => ['text-nowrap'],
                    'attrs' => [
                        'href' => $url,
                    ],
                ]);
            }
            echo '</div>';
        }
    ?>
</div>
