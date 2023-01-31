<?php
use Cake\Routing\Route\DashedRoute;
use Cake\Routing\RouteBuilder;

$routes->plugin(
    'Tags',
    ['path' => '/tags'],
    function ($routes) {
        $routes->setRouteClass(DashedRoute::class);

        $routes->connect(
            '/{action}/*',
            ['controller' => 'Tags']
        );

        $routes->get('/', ['controller' => 'Tags', 'action' => 'index']);
        // $routes->get('/{id}', ['controller' => 'Tags', 'action' => 'view']);
        // $routes->put('/{id}', ['controller' => 'Tags', 'action' => 'edit']);
    }
);
$routes->plugin(
    'Tags',
    ['path' => '/Tags'],
    function ($routes) {
        $routes->setRouteClass(DashedRoute::class);

        $routes->connect(
            '/{action}/*',
            ['controller' => 'Tags']
        );

        $routes->get('/', ['controller' => 'Tags', 'action' => 'index']);
        // $routes->get('/{id}', ['controller' => 'Tags', 'action' => 'view']);
        // $routes->put('/{id}', ['controller' => 'Tags', 'action' => 'edit']);
    }
);