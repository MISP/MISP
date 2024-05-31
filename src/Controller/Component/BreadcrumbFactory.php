<?php

namespace App\Controller\Component;

use Cake\ORM\TableRegistry;
use Cake\Utility\Inflector;

class BreadcrumbFactory
{
    private $endpoints = [];
    public $iconToTableMapping = [];

    public function __construct($iconToTableMapping)
    {
        $this->iconToTableMapping = $iconToTableMapping;
    }

    public function defaultCRUD(string $controller, string $action, array $overrides = []): array
    {
        $table = TableRegistry::getTableLocator()->get($controller);
        $item = [];
        if ($action === 'index') {
            $item = $this->genRouteConfig(
                $controller,
                $action,
                [
                    'label' => __('{0} index', Inflector::humanize($controller)),
                    'url' => "/{$controller}/index",
                    'icon' => $this->iconToTableMapping[$controller]
                ]
            );
        } else if ($action === 'view') {
            $item = $this->genRouteConfig(
                $controller,
                $action,
                [
                    'label' => __('View'),
                    'icon' => 'eye',
                    'url' => "/{$controller}/view/{{id}}",
                    'url_vars' => ['id' => 'id'],
                    'textGetter' => !empty($table->getDisplayField()) ? $table->getDisplayField() : 'id',
                ]
            );
        } else if ($action === 'add') {
            $item = $this->genRouteConfig(
                $controller,
                $action,
                [
                    'label' => __('Create {0}', $controller),
                    'icon' => 'plus',
                    'url' => "/{$controller}/add",
                ]
            );
        } else if ($action === 'edit') {
            $item = $this->genRouteConfig(
                $controller,
                $action,
                [
                    'label' => __('Edit'),
                    'icon' => 'edit',
                    'url' => "/{$controller}/edit/{{id}}",
                    'url_vars' => ['id' => 'id'],
                    'textGetter' => !empty($table->getDisplayField()) ? $table->getDisplayField() : 'id',
                ]
            );
        } else if ($action === 'delete') {
            $item = $this->genRouteConfig(
                $controller,
                $action,
                [
                    'label' => __('Delete'),
                    'icon' => 'trash',
                    'url' => "/{$controller}/delete/{{id}}",
                    'url_vars' => ['id' => 'id'],
                    'textGetter' => !empty($table->getDisplayField()) ? $table->getDisplayField() : 'id',
                    'variant' => 'danger',
                ]
            );
        }
        $item['route_path'] = "{$controller}:{$action}";
        $item = array_merge($item, $overrides);
        return $item;
    }

    public function genRouteConfig($controller, $action, $config = [])
    {
        $routeConfig = [
            'controller' => $controller,
            'action' => $action,
            'route_path' => "{$controller}:{$action}",
        ];
        $routeConfig = $this->addIfNotEmpty($routeConfig, $config, 'url');
        $routeConfig = $this->addIfNotEmpty($routeConfig, $config, 'url_vars');
        $routeConfig = $this->addIfNotEmpty($routeConfig, $config, 'icon');
        $routeConfig = $this->addIfNotEmpty($routeConfig, $config, 'label');
        $routeConfig = $this->addIfNotEmpty($routeConfig, $config, 'textGetter');
        $routeConfig = $this->addIfNotEmpty($routeConfig, $config, 'badge');
        $routeConfig = $this->addIfNotEmpty($routeConfig, $config, 'variant');
        $routeConfig = $this->addIfNotEmpty($routeConfig, $config, 'is-go-to');
        $routeConfig = $this->addIfNotEmpty($routeConfig, $config, 'isPOST');
        return $routeConfig;
    }

    private function addIfNotEmpty($arr, $data, $key, $default = null)
    {
        if (!empty($data[$key])) {
            $arr[$key] = $data[$key];
        } else {
            if (!is_null($default)) {
                $arr[$key] = $default;
            }
        }
        return $arr;
    }

    public function addRoute(string $controller, string $action, array $config = [])
    {
        $this->endpoints[$controller][$action] = $this->genRouteConfig($controller, $action, $config);
    }

    public function setDefaultCRUDForModel($controller)
    {
        $this->addRoute($controller, 'index', $this->defaultCRUD($controller, 'index'));
        $this->addRoute($controller, 'view', $this->defaultCRUD($controller, 'view'));
        $this->addRoute($controller, 'add', $this->defaultCRUD($controller, 'add'));
        $this->addRoute($controller, 'edit', $this->defaultCRUD($controller, 'edit'));
        $this->addRoute($controller, 'delete', $this->defaultCRUD($controller, 'delete'));

        $this->addParent($controller, 'view', $controller, 'index');
        $this->addParent($controller, 'add', $controller, 'index');
        $this->addParent($controller, 'edit', $controller, 'index');
        $this->addParent($controller, 'delete', $controller, 'index');

        $this->addSelfLink($controller, 'view');
        $this->addLink($controller, 'view', $controller, 'edit');
        $this->addLink($controller, 'edit', $controller, 'view');
        $this->addSelfLink($controller, 'edit');

        // $this->addAction($controller, 'index', $controller, 'add');
        // $this->addAction($controller, 'view', $controller, 'add');
        $this->addAction($controller, 'view', $controller, 'delete');
        $this->addAction($controller, 'edit', $controller, 'add');
        $this->addAction($controller, 'edit', $controller, 'delete');
    }

    public function get($controller, $action)
    {
        if (empty($this->endpoints[$controller]) || empty($this->endpoints[$controller][$action])) {
            throw new \Exception(sprintf("Tried to add a reference to %s:%s which does not exists", $controller, $action), 1);
        }
        return $this->endpoints[$controller][$action];
    }

    public function getEndpoints()
    {
        return $this->endpoints;
    }

    public function addParent(string $sourceController, string $sourceAction, string $targetController, string $targetAction, $overrides = [])
    {
        $routeSourceConfig = $this->get($sourceController, $sourceAction);
        $routeTargetConfig = $this->get($targetController, $targetAction);
        $overrides = $this->execClosureIfNeeded($overrides, $routeTargetConfig);
        if (!is_array($overrides)) {
            throw new \Exception(sprintf("Override closure for %s:%s -> %s:%s must return an array", $sourceController, $sourceAction, $targetController, $targetAction), 1);
        }
        $routeTargetConfig = array_merge($routeTargetConfig, $overrides);
        $parents = array_merge($routeSourceConfig['after'] ?? [], $routeTargetConfig);
        $this->endpoints[$sourceController][$sourceAction]['after'] = $parents;
    }

    public function addSelfLink(string $controller, string $action, array $options = [])
    {
        $this->addLink(
            $controller,
            $action,
            $controller,
            $action,
            array_merge(
                $options,
                [
                    'selfLink' => true,
                ]
            )
        );
    }

    public function addLink(string $sourceController, string $sourceAction, string $targetController, string $targetAction, $overrides = [])
    {
        $routeSourceConfig = $this->getRouteConfig($sourceController, $sourceAction, true);
        $routeTargetConfig = $this->getRouteConfig($targetController, $targetAction);
        $overrides = $this->execClosureIfNeeded($overrides, $routeTargetConfig);
        if (is_null($overrides)) {
            // Overrides is null, the link should not be added
            return;
        }
        if (!is_array($overrides)) {
            throw new \Exception(sprintf("Override closure for %s:%s -> %s:%s must return an array", $sourceController, $sourceAction, $targetController, $targetAction), 1);
        }
        $routeTargetConfig = array_merge($routeTargetConfig, $overrides);
        $links = array_merge($routeSourceConfig['links'] ?? [], [$routeTargetConfig]);
        $this->endpoints[$sourceController][$sourceAction]['links'] = $links;
    }

    public function addCustomLink(string $sourceController, string $sourceAction, string $targetUrl, string $label, $overrides = [])
    {
        $routeSourceConfig = $this->getRouteConfig($sourceController, $sourceAction, true);
        $overrides = $this->execClosureIfNeeded($overrides, $routeSourceConfig);
        if (!is_array($overrides)) {
            throw new \Exception(sprintf("Override closure for custom action %s:%s must return an array", $sourceController, $sourceAction), 1);
        }
        $linkConfig = [
            'url' => $targetUrl,
            'icon' => 'link',
            'label' => $label,
            'route_path' => 'foo:bar'
        ];
        $linkConfig = array_merge($linkConfig, $overrides);
        $links = array_merge($routeSourceConfig['links'] ?? [], [$linkConfig]);
        $this->endpoints[$sourceController][$sourceAction]['links'] = $links;
    }

    public function addAction(string $sourceController, string $sourceAction, string $targetController, string $targetAction, $overrides = [])
    {
        $routeSourceConfig = $this->getRouteConfig($sourceController, $sourceAction, true);
        $routeTargetConfig = $this->getRouteConfig($targetController, $targetAction);
        $overrides = $this->execClosureIfNeeded($overrides, $routeTargetConfig);
        if (!is_array($overrides)) {
            throw new \Exception(sprintf("Override closure for %s:%s -> %s:%s must return an array", $sourceController, $sourceAction, $targetController, $targetAction), 1);
        }
        $routeTargetConfig = array_merge($routeTargetConfig, $overrides);
        $links = array_merge($routeSourceConfig['actions'] ?? [], [$routeTargetConfig]);
        $this->endpoints[$sourceController][$sourceAction]['actions'] = $links;
    }

    /**
     * Add a custom action to the action bar
     *
     * @param string $sourceController The source controller name
     * @param string $sourceAction The source action name
     * @param string $targetUrl The target URL for that action
     * @param string $label The text to be displayed in the button
     * @param array $overrides Optional overrides to apply on this action
     * @return void
     */
    public function addCustomAction(string $sourceController, string $sourceAction, string $targetUrl, string $label, $overrides = [])
    {
        $routeSourceConfig = $this->getRouteConfig($sourceController, $sourceAction, true);
        $overrides = $this->execClosureIfNeeded($overrides, $routeSourceConfig);
        if (!is_array($overrides)) {
            throw new \Exception(sprintf("Override closure for custom action %s:%s must return an array", $sourceController, $sourceAction), 1);
        }
        $actionConfig = [
            'url' => $targetUrl,
            'label' => $label,
            'route_path' => 'foo:bar'
        ];
        $actionConfig = array_merge($actionConfig, $overrides);
        $links = array_merge($routeSourceConfig['actions'] ?? [], [$actionConfig]);
        $this->endpoints[$sourceController][$sourceAction]['actions'] = $links;
    }

    public function removeLink(string $sourceController, string $sourceAction, string $targetController, string $targetAction)
    {
        $routeSourceConfig = $this->getRouteConfig($sourceController, $sourceAction, true);
        if (!empty($routeSourceConfig['links'])) {
            foreach ($routeSourceConfig['links'] as $i => $routeConfig) {
                if ($routeConfig['controller'] == $targetController && $routeConfig['action'] == $targetAction) {
                    unset($routeSourceConfig['links'][$i]);
                    $this->endpoints[$sourceController][$sourceAction]['links'] = $routeSourceConfig['links'];
                    break;
                }
            }
        }
    }

    public function removeAction(string $sourceController, string $sourceAction, string $targetController, string $targetAction)
    {
        $routeSourceConfig = $this->getRouteConfig($sourceController, $sourceAction, true);
        if (!empty($routeSourceConfig['actions'])) {
            foreach ($routeSourceConfig['actions'] as $i => $routeConfig) {
                if ($routeConfig['controller'] == $targetController && $routeConfig['action'] == $targetAction) {
                    unset($routeSourceConfig['actions'][$i]);
                    $this->endpoints[$sourceController][$sourceAction]['actions'] = $routeSourceConfig['actions'];
                    break;
                }
            }
        }
    }

    public function registerGoToMenuConfig(string $sourceController, string $sourceAction, string $goToID, array $config = []): void
    {
        $this->endpoints[$sourceController][$sourceAction]['goToMenu'][$goToID] = $config;
    }

    public function registerLinkMenuConfig(string $sourceController, string $sourceAction, string $menuID, array $config = []): void
    {
        $this->endpoints[$sourceController][$sourceAction]['linkMenu'][$menuID] = $config;
    }

    public function registerActionMenuConfig(string $sourceController, string $sourceAction, string $menuID, array $config = []): void
    {
        $this->endpoints[$sourceController][$sourceAction]['actionMenu'][$menuID] = $config;
    }

    public function getRouteConfig($controller, $action, $fullRoute = false)
    {
        $routeConfig = $this->get($controller, $action);
        if (empty($fullRoute)) {
            unset($routeConfig['after']);
            unset($routeConfig['links']);
            unset($routeConfig['actions']);
        }
        return $routeConfig;
    }

    private function execClosureIfNeeded($closure, $routeConfig = [])
    {
        if (is_callable($closure)) {
            return $closure($routeConfig);
        }
        return $closure;
    }
}
