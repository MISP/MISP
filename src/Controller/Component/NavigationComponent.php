<?php

namespace App\Controller\Component;

use Cake\Controller\Component;
use Cake\Core\Configure;
use Cake\Core\App;
use Cake\Utility\Inflector;
use Cake\Utility\Hash;
use Cake\Filesystem\Folder;
use Cake\Routing\Router;
use Cake\ORM\TableRegistry;
use Exception;

use SidemenuNavigation\Sidemenu;
require_once(APP . 'Controller' . DS . 'Component' . DS . 'Navigation' . DS . 'sidemenu.php');

class NavigationComponent extends Component
{
    private $currentUser = null;
    public $breadcrumb = null;
    public $fullBreadcrumb = null;
    public $iconToTableMapping = [
        // 'Organisations' => 'building',
        // 'EncryptionKeys' => 'key',
        // 'SharingGroups' => 'user-friends',
        // 'Connectivity' => 'network-wired',
        // 'Roles' => 'id-badge',
        // 'Users' => 'users',
        // 'UserSettings' => 'user-cog',
        // 'Inbox' => 'inbox',
        // 'Instance' => 'server',
        // 'Tags' => 'tags',
        // 'API' => 'code',
        // 'Feeds' => 'rss',
        // 'Events' => 'project-diagram',
        // 'Context' => 'book-reader',
        // 'Insights' => 'lightbulb',

        'Events' => 'envelope-open-text',
        'Attributes' => 'cube',
        'PeriodicReport' => 'newspaper',
        'Dashboard' => 'chart-line',
        'Proposals' => 'pen-square',
        'Taxonomies' => 'book',
        'Galaxies' => 'atlas',
        'ObjectTemplates' => 'ruler-combined',
        'Tags' => 'tag',
        'TagCollections' => 'tags',
        'Templates' => 'pencil-ruler',
        // 'Warninglists' => ['html' => '<span class="fa-stack fa-2x"><i class="fa-solid fa-file fa-stack-2x"></i><i class="fa-solid fa-exclamation-triangle fa-stack-1x fa-inverse"></i></span>'],
        'Warninglists' => 'file',
        'Workflows' => 'sitemap',
        'CorrelationsExclusions' => 'ban',
        'DecayingModels' => 'hourglass',
        'ImportRegexp' => 'file-import',
        'SignatureAllowedlists' => 'fingerprint',
        'NoticeLists' => 'list-alt',
        'Correlations' => 'project-diagram',
        'Servers' => 'server',
        'Communities' => 'address-book',
        'Cerebrate' => 'server',
        // 'Cerebrate' => ['add-cerebrate-icon'],
        'TaxiiServers' => 'server',
        // 'TaxiiServers' => ['add-cerebrate-icon'],
        'ServerSettings' => 'cogs',
        'Jobs' => 'robot',
        'BlockRules' => 'ban',
        'Logs' => 'history',
        'AccessLogs' => 'history',
        'ApplicationLogs' => 'history',
        'OrganisationsRules' => 'ban',
        'EventsBlockRules' => 'ban',
        'SharingGroups' => 'user-friends',
        'Organisations' => 'building',
        'Users' => 'users',
        'Feeds' => 'rss',
        'Roles' => 'id-badge',
        'API' => 'code',
        'UserSettings' => 'user-cog',
        'Inbox' => 'inbox',
    ];

    public function initialize(array $config): void
    {
        $this->request = $config['request'];
    }

    public function beforeRender($event)
    {
        // $this->fullBreadcrumb = null;
        $this->fullBreadcrumb = $this->genBreadcrumb();
    }

    public function getSideMenu(): array
    {
        $sidemenu = new Sidemenu($this->iconToTableMapping, $this->request);
        $sidemenu = $sidemenu->get();
        $sidemenu = $this->addUserBookmarks($sidemenu);
        return $sidemenu;
    }


    public function addUserBookmarks($sidemenu): array
    {
        $bookmarks = null;
        //$bookmarks = $this->getUserBookmarks();
        $sidemenu = array_merge([
            '__bookmarks' => $bookmarks
        ], $sidemenu);
        return $sidemenu;
    }

    public function getUserBookmarks(): array
    {
        $userSettingTable = TableRegistry::getTableLocator()->get('UserSettings');
        $setting = $userSettingTable->getSettingByName($this->request->getAttribute('identity'), 'ui.bookmarks');
        $bookmarks = is_null($setting) ? [] : json_decode($setting->value, true);

        $links = array_map(function($bookmark) {
            return [
                'name' => $bookmark['name'],
                'label' => $bookmark['label'],
                'url' => $bookmark['url'],
            ];
        }, $bookmarks);
        return $links;
    }

    public function getBreadcrumb(): array
    {
        $controller = $this->request->getParam('controller');
        $action = $this->request->getParam('action');
        if (empty($this->fullBreadcrumb[$controller][$action])) {
            return [[
                'label' => $controller,
                'url' => Router::url(['controller' => $controller, 'action' => $action]),
            ]]; // no breadcrumb defined for this endpoint
        }
        $currentRoute = $this->fullBreadcrumb[$controller][$action];
        $breadcrumbPath = $this->getBreadcrumbPath($currentRoute);
        return $breadcrumbPath;
    }

    public function getBreadcrumbPath(array $currentRoute): array
    {
        $path = [];
        $visitedURL = [];
        while (empty($visitedURL[$currentRoute['url']])) {
            $visitedURL[$currentRoute['url']] = true;
            $path[] = $currentRoute;
            if (!empty($currentRoute['after'])) {
                if (is_callable($currentRoute['after'])) {
                    $route = $currentRoute['after']();
                } else {
                    $route = $currentRoute['after'];
                }
                if (empty($route)) {
                    continue;
                }
                $currentRoute = $route;
            }
        }
        $path = array_reverse($path);
        return $path;
    }

    public function genBreadcrumb(): array
    {
        $request = $this->request;
        $bcf = new BreadcrumbFactory($this->iconToTableMapping);
        $fullConfig = $this->getFullConfig($bcf, $this->request);
        return $fullConfig;
    }

    private function loadNavigationClasses($bcf, $request)
    {
        $navigationClasses = [];
        $navigationDir = new Folder(APP . DS . 'Controller' . DS . 'Component' . DS . 'Navigation');
        $navigationFiles = $navigationDir->find('.*\.php', true);
        foreach ($navigationFiles as $navigationFile) {
            if ($navigationFile == 'base.php' || $navigationFile == 'sidemenu.php') {
                continue;
            }
            $navigationClassname = str_replace('.php', '', $navigationFile);
            require_once(APP . 'Controller' . DS . 'Component' . DS . 'Navigation' . DS . $navigationFile);
            $reflection = new \ReflectionClass("BreadcrumbNavigation\\{$navigationClassname}Navigation");
            $viewVars = $this->_registry->getController()->viewBuilder()->getVars();
            $navigationClasses[$navigationClassname] = $reflection->newInstance($bcf, $request, $viewVars);
            $navigationClasses[$navigationClassname]->setCurrentUser($this->currentUser);
        }
        return $navigationClasses;
    }

    public function getFullConfig($bcf, $request)
    {
        $navigationClasses = $this->loadNavigationClasses($bcf, $request);
        $CRUDControllers = [
            //'Individuals',
            'Organisations',
            'SharingGroups',
            'Roles',
            'Users',
            'Tags',
            'UserSettings',
        ];
        foreach ($CRUDControllers as $controller) {
            $bcf->setDefaultCRUDForModel($controller);
        }

        foreach ($navigationClasses as $className => $class) {
            $class->addRoutes();
        }
        foreach ($navigationClasses as $className => $class) {
            $class->addParents();
        }
        foreach ($navigationClasses as $className => $class) {
            $class->addLinks();
        }
        foreach ($navigationClasses as $className => $class) {
            $class->addActions();
        }
        return $bcf->getEndpoints();
    }
}

class BreadcrumbFactory
{
    private $endpoints = [];
    private $iconToTableMapping = [];

    public function __construct($iconToTableMapping)
    {
        $this->iconToTableMapping = $iconToTableMapping;
    }

    public function defaultCRUD(string $controller, string $action, array $overrides = []): array
    {
        $table = TableRegistry::getTableLocator()->get($controller);
        $item = [];
        if ($action === 'index') {
            $item = $this->genRouteConfig($controller, $action, [
                'label' => __('{0} index', Inflector::humanize($controller)),
                'url' => "/{$controller}/index",
                'icon' => $this->iconToTableMapping[$controller]
            ]);
        } else if ($action === 'view') {
            $item = $this->genRouteConfig($controller, $action, [
                'label' => __('View'),
                'icon' => 'eye',
                'url' => "/{$controller}/view/{{id}}",
                'url_vars' => ['id' => 'id'],
                'textGetter' => !empty($table->getDisplayField()) ? $table->getDisplayField() : 'id',
            ]);
        } else if ($action === 'add') {
            $item = $this->genRouteConfig($controller, $action, [
                'label' => __('Create {0}', $controller),
                'icon' => 'plus',
                'url' => "/{$controller}/add",
            ]);
        } else if ($action === 'edit') {
            $item = $this->genRouteConfig($controller, $action, [
                'label' => __('Edit'),
                'icon' => 'edit',
                'url' => "/{$controller}/edit/{{id}}",
                'url_vars' => ['id' => 'id'],
                'textGetter' => !empty($table->getDisplayField()) ? $table->getDisplayField() : 'id',
            ]);
        } else if ($action === 'delete') {
            $item = $this->genRouteConfig($controller, $action, [
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => "/{$controller}/delete/{{id}}",
                'url_vars' => ['id' => 'id'],
                'textGetter' => !empty($table->getDisplayField()) ? $table->getDisplayField() : 'id',
                'variant' => 'danger',
            ]);
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

    public function addRoute($controller, $action, $config = []) {
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

        $this->addAction($controller, 'index', $controller, 'add');
        $this->addAction($controller, 'view', $controller, 'add');
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
        $overrides = $this->execClosureIfNeeded($overrides, $routeSourceConfig);
        if (!is_array($overrides)) {
            throw new \Exception(sprintf("Override closure for %s:%s -> %s:%s must return an array", $sourceController, $sourceAction, $targetController, $targetAction), 1);
        }
        $routeTargetConfig = array_merge($routeTargetConfig, $overrides);
        $parents = array_merge($routeSourceConfig['after'] ?? [], $routeTargetConfig);
        $this->endpoints[$sourceController][$sourceAction]['after'] = $parents;
    }

    public function addSelfLink(string $controller, string $action, array $options=[])
    {
        $this->addLink($controller, $action, $controller, $action, array_merge($options, [
            'selfLink' => true,
        ]));
    }

    public function addLink(string $sourceController, string $sourceAction, string $targetController, string $targetAction, $overrides = [])
    {
        $routeSourceConfig = $this->getRouteConfig($sourceController, $sourceAction, true);
        $routeTargetConfig = $this->getRouteConfig($targetController, $targetAction);
        $overrides = $this->execClosureIfNeeded($overrides, $routeSourceConfig);
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
        $links = array_merge($routeSourceConfig['links'] ?? [], [[
            'url' => $targetUrl,
            'icon' => 'link',
            'label' => $label,
            'route_path' => 'foo:bar'
        ]]);
        $this->endpoints[$sourceController][$sourceAction]['links'] = $links;
    }

    public function addAction(string $sourceController, string $sourceAction, string $targetController, string $targetAction, $overrides = [])
    {
        $routeSourceConfig = $this->getRouteConfig($sourceController, $sourceAction, true);
        $routeTargetConfig = $this->getRouteConfig($targetController, $targetAction);
        $overrides = $this->execClosureIfNeeded($overrides, $routeSourceConfig);
        if (!is_array($overrides)) {
            throw new \Exception(sprintf("Override closure for %s:%s -> %s:%s must return an array", $sourceController, $sourceAction, $targetController, $targetAction), 1);
        }
        $routeTargetConfig = array_merge($routeTargetConfig, $overrides);
        $links = array_merge($routeSourceConfig['actions'] ?? [], [$routeTargetConfig]);
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

    private function execClosureIfNeeded($closure, $routeConfig=[])
    {
        if (is_callable($closure)) {
            return $closure($routeConfig);
        }
        return $closure;
    }
}
