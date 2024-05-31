<?php

namespace App\Controller\Component;

use App\Controller\Component\BreadcrumbFactory;
use App\Controller\Component\Navigation\SidemenuNavigation;
use Cake\Controller\Component;
use Cake\ORM\TableRegistry;
use Cake\Routing\Router;
use DirectoryIterator;

class NavigationComponent extends Component
{
    const NAVIGATION_FILES_DIR = APP . DS . 'Controller' . DS . 'Component' . DS . 'Navigation';

    private $currentUser = null;
    public $breadcrumb = null;
    public $fullBreadcrumb = null;
    public $iconToTableMapping = [
        'Events' => 'envelope-open-text',
        'Attributes' => 'cube',
        'Objects' => 'cubes',
        'EventReports' => 'file-lines',
        'PeriodicReport' => 'newspaper',
        'Dashboard' => 'chart-line',
        'Proposals' => 'pen-square',
        'Taxonomies' => 'book',
        'Galaxies' => 'atlas',
        'ObjectTemplates' => 'ruler-combined',
        'Tags' => 'tag',
        'TagCollections' => 'tags',
        'Templates' => 'pencil-ruler',
        'Warninglists' => [
            'stacked' => [
                ['icon' => 'file'],
                ['icon' => 'exclamation-triangle', 'class' => 'fa-inverse', 'style' => 'top: 0.2em;'],
            ]

        ],
        'Workflows' => 'sitemap',
        'CorrelationsExclusions' => [
            'stacked' => [
                ['icon' => 'ban'],
                ['icon' => 'project-diagram', 'class' => '', 'style' => ''],
            ]

        ],
        'DecayingModels' => 'hourglass-end',
        'ImportRegexp' => 'file-import',
        'SignatureAllowedlists' => 'fingerprint',
        'Noticelists' => 'list',
        'Correlations' => 'project-diagram',
        'Servers' => 'network-wired',
        'Communities' => 'handshake-simple',
        'Cerebrates' => ['image' => '/img/cerebrate-icon-purple.png',],
        'TaxiiServers' => ['image' => '/img/taxii-icon.png',],
        'ServerSettings' => 'cogs',
        'Jobs' => 'robot',
        'BlockRules' => 'ban',
        'Logs' => 'history',
        'AccessLogs' => 'door-open',
        'ApplicationLogs' => 'list-ul',
        'OrganisationsRules' => [
            'stacked' => [
                ['icon' => 'ban', 'class' => 'text-muted',],
                ['icon' => 'building', 'class' => 'text-body',]
            ]

        ],
        'EventsBlockRules' => [
            'stacked' => [
                ['icon' => 'ban', 'class' => 'text-muted',],
                ['icon' => 'envelope-open-text', 'class' => 'text-body',],
            ]

        ],
        'SharingGroups' => 'users-rectangle',
        'Organisations' => 'building',
        'Users' => 'users',
        'Feeds' => 'rss',
        'Roles' => 'id-badge',
        'API' => 'code',
        'UserSettings' => 'user-cog',
        'Inbox' => 'inbox',
        'RestClient' =>  [
            'stacked' => [
                ['icon' => 'cloud'],
                ['icon' => 'cog', 'class' => 'fa-inverse']
            ]

        ],
    ];
    protected $defaultCRUDControllers = [
        //'Individuals',
        'Organisations',
        'SharingGroups',
        'Roles',
        'Users',
        'Tags',
        'UserSettings',
        // 'Events',
        'Noticelists',
        'ObjectTemplates',
        'Cerebrates'
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
        $sidemenu = new SidemenuNavigation($this->iconToTableMapping, $this->request);
        $sidemenu = $sidemenu->get();
        $sidemenu = $this->addUserBookmarks($sidemenu);
        return $sidemenu;
    }


    public function addUserBookmarks($sidemenu): array
    {
        $bookmarks = null;
        //$bookmarks = $this->getUserBookmarks();
        $sidemenu = array_merge(
            [
                '__bookmarks' => $bookmarks
            ],
            $sidemenu
        );
        return $sidemenu;
    }

    public function getUserBookmarks(): array
    {
        $userSettingTable = TableRegistry::getTableLocator()->get('UserSettings');
        $setting = $userSettingTable->getSettingByName($this->request->getAttribute('identity'), 'ui.bookmarks');
        $bookmarks = is_null($setting) ? [] : json_decode($setting->value, true);

        $links = array_map(
            function ($bookmark) {
                return [
                    'name' => $bookmark['name'],
                    'label' => $bookmark['label'],
                    'url' => $bookmark['url'],
                ];
            },
            $bookmarks
        );
        return $links;
    }

    public function getIconToTableMapping(): array
    {
        return $this->iconToTableMapping;
    }

    public function getBreadcrumb(): array
    {
        $controller = $this->request->getParam('controller');
        $action = $this->request->getParam('action');
        if (empty($this->fullBreadcrumb[$controller][$action])) {
            return [
                [
                    'label' => $controller,
                    'url' => Router::url(['controller' => $controller, 'action' => $action]),
                ]

            ]; // no breadcrumb defined for this endpoint
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
        $dir = new DirectoryIterator(self::NAVIGATION_FILES_DIR);
        foreach ($dir as $fileinfo) {
            if ($fileinfo->isFile()) {
                if ($fileinfo->getFilename() == 'BaseNavigation.php' || $fileinfo->getFilename() == 'SidemenuNavigation.php') {
                    continue;
                }
                $navigationClassname = str_replace('.php', '', $fileinfo->getFilename());
                require_once(APP . 'Controller' . DS . 'Component' . DS . 'Navigation' . DS . $fileinfo->getFilename());
                $reflection = new \ReflectionClass("App\\Controller\\Component\\Navigation\\{$navigationClassname}");
                $viewVars = $this->_registry->getController()->viewBuilder()->getVars();
                $navigationClasses[$navigationClassname] = $reflection->newInstance($bcf, $request, $viewVars);
                $navigationClasses[$navigationClassname]->setCurrentUser($this->currentUser);
            }
        }
        return $navigationClasses;
    }

    public function getFullConfig($bcf, $request)
    {
        $navigationClasses = $this->loadNavigationClasses($bcf, $request);
        $CRUDControllers = $this->defaultCRUDControllers;
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
