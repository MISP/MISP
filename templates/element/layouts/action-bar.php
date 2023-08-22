<?php

use Cake\Routing\Router;
use Cake\Utility\Inflector;

?>

<div class="action-bar d-flex flex-nowrap flex-row mt-2 mb-1 rounded">
    <?php
        if (!empty($actions)) {
            echo '<div>';
            $badgeNumber = 0;
            $actionsInMenu = [];
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
                $buttonConfig = [
                    'text' => h($actionEntry['label']),
                    'icon' => h($actionEntry['icon'] ?? false),
                    'variant' => $actionEntry['variant'] ?? 'primary',
                    'class' => ['text-nowrap'],
                    'size' => 'sm',
                    'onclick' => $onclickFunction,
                    'badge' => $buttonBadge,
                ];
                if (!empty($actionEntry['menu'])) {
                    if (!empty($actionEntry['menu_primary'])) {
                        $buttonConfig['_menu_primary'] = $actionEntry['menu_primary'];
                    }
                    $actionsInMenu[$actionEntry['menu']][] = $buttonConfig;
                } else {
                    echo $this->Bootstrap->button($buttonConfig, $buttonBadge);
                }
            }
            if (!empty($actionsInMenu)) {
                foreach ($actionsInMenu as $menuID => $actions) {
                    $defaultMenuConfig = [
                        'text' => Inflector::humanize($menuID),
                        'variant' => 'primary',
                        'outline' => true,
                        'size' => 'sm',
                    ];
                    $actionMenuRootConfig = $actionMenu[$menuID] ?? [];
                    if (empty($actionMenuRootConfig)) {
                        $primaryItem = array_filter(
                            $actions,
                            function ($action) {
                            return !empty($action['_menu_primary']);
                            }
                        );
                        if (!empty($primaryItem)) {
                            $actionMenuRootConfig = $primaryItem[0];
                            $actionMenuRootConfig['split'] = true;
                        }
                    }
                    $menuConfig = array_merge($defaultMenuConfig, $actionMenuRootConfig);
                    $menuConfig['text'] = $menuConfig['label'] ?? $menuConfig['text'];
                    $actions = array_map(
                        function($action) {
                        $action['outline'] = true;
                        return $action;
                        },
                        $actions
                    );
                    echo $this->Bootstrap->dropdownMenu(
                        [
                        'dropdown-class' => '',
                        'alignment' => 'start',
                        'direction' => 'down',
                        'button' => $menuConfig,
                        'submenu_direction' => 'end',
                        'attrs' => [],
                        'menu' => $actions,
                        ]
                    );
                }
            }
            echo '</div>';
        }

        if (!empty($links)) {
            $goToLinks = [];
            $linksInMenu = [];
            echo '<div class="ms-auto">';
            echo '<div class="d-flex gap-1">';
            foreach ($links as $i => $linkEntry) {
                if (!empty($linkEntry['is-go-to'])) {
                    if (is_bool($linkEntry['is-go-to'])) {
                        $goToLinks['_root'][] = $linkEntry;
                    } else {
                        $goToLinks[$linkEntry['is-go-to']][] = $linkEntry;
                    }
                    continue;
                }
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
                $buttonBadge = !empty($linkEntry['badge']) ? $this->Bootstrap->badge($linkEntry['badge']) : '';
                $buttonConfig = [
                    'nodeType' => 'a',
                    'text' => $linkEntry['label'],
                    'icon' => $linkEntry['icon'],
                    'badge' => $linkEntry['badge'] ?? false,
                    'variant' => 'link',
                    'outline' => $active,
                    'class' => ['text-nowrap', 'text-decoration-none', 'btn-link-hover-shadow'],
                    'size' => 'sm',
                    'attrs' => [
                        'href' => $url,
                    ],
                ];
                if (!empty($linkEntry['menu'])) {
                    $linksInMenu[$linkEntry['menu']][] = $buttonConfig;
                } else {
                    echo $this->Bootstrap->button($buttonConfig, $buttonBadge);
                }
            }
            if (!empty($linksInMenu)) {
                foreach ($linksInMenu as $menuID => $links) {
                    $defaultMenuConfig = [
                        'text' => Inflector::humanize($menuID),
                        'variant' => 'secondary',
                        'size' => 'sm',
                        'outline' => true,
                    ];
                    $menuConfig = array_merge($defaultMenuConfig, $linkMenu[$menuID] ?? []);
                    $menuConfig['text'] = $menuConfig['label'] ?: $menuConfig['text'];
                    $links = array_map(
                        function($link) {
                        $action['outline'] = true;
                        return $link;
                        },
                        $links
                    );
                    echo $this->Bootstrap->dropdownMenu(
                        [
                        'dropdown-class' => '',
                        'alignment' => 'end',
                        'direction' => 'down',
                        'button' => $menuConfig,
                        'submenu_direction' => 'end',
                        'attrs' => [],
                        'menu' => $links,
                        ]
                    );
                }
            }
            echo '</div>';

            if (!empty($goToLinks)) {
                $menu = [];
                foreach ($goToLinks as $menuID => $links) {
                    $jumpToButtons = array_map(
                        function($link) {
                        $url = Router::url($link['url']);
                        return [
                            'nodeType' => 'a',
                            'text' => h($link['label']),
                            'variant' => 'link',
                            'icon' => h($link['icon']),
                            'class' => ['text-nowrap'],
                            'attrs' => [
                                'href' => h($url),
                            ],
                        ];
                        },
                        $links
                    );
                    if ($menuID === '_root') {
                        $menu = array_merge($menu, $jumpToButtons);
                    } else {
                        $subMenuConfig = $goToMenu[$menuID] ?? [];
                        $subMenu = [
                            'nodeType' => 'a',
                            'text' => h($subMenuConfig['label']),
                            'variant' => h($subMenuConfig['variant'] ?? 'link'),
                            'icon' => h($subMenuConfig['icon']),
                            'class' => ['text-nowrap'],
                            'keepOpen' => true,
                            'menu' => $jumpToButtons
                        ];
                        $menu[] = $subMenu;
                    }
                }
                echo $this->Bootstrap->dropdownMenu(
                    [
                    'dropdown-class' => '',
                    'alignment' => 'end',
                    'direction' => 'down',
                    'button' => [
                        'text' => 'Go To',
                        'variant' => 'secondary',
                        'icon' => 'location-arrow',
                    ],
                    'submenu_direction' => 'start',
                    'attrs' => [],
                    'menu' => $menu,
                    ]
                );
            }
            echo '</div>';
        }
    ?>
</div>
