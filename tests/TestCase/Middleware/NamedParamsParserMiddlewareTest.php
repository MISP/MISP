<?php

declare(strict_types=1);

namespace App\Test\TestCase\Middleware;

use Cake\Core\Configure;
use Cake\Core\HttpApplicationInterface;
use Cake\Http\ServerRequestFactory;
use Cake\Routing\Middleware\RoutingMiddleware;
use App\Middleware\NamedParamsParserMiddleware;
use Cake\Routing\RouteBuilder;
use Cake\Routing\Router;
use Cake\TestSuite\TestCase;
use App\Test\Helper\TestApp\Application;
use App\Test\Helper\TestApp\TestRequestHandler;

class NamedParamsParserMiddlewareTest extends TestCase
{
    protected $log = [];

    /**
     * @var \Cake\Routing\RouteBuilder
     */
    protected $builder;

    public function setUp(): void
    {
        parent::setUp();

        Router::reload();
        $this->builder = Router::createRouteBuilder('/');
        $this->builder->connect('/articles', ['controller' => 'Articles', 'action' => 'index']);
        $this->log = [];

        Configure::write('App.base', '');
    }

    public function testNamedParametersAreParsed(): void
    {
        Configure::write('NamedParams', [
            'articles.index' => ['limit', 'order'],
        ]);

        $this->builder->registerMiddleware('namedParamsParser', new NamedParamsParserMiddleware());
        $this->builder->applyMiddleware('namedParamsParser');

        // Add a test middleware layer to ensure NamedParamsParserMiddleware works
        $this->builder->registerMiddleware('test', function ($request, $handler) {

            $this->assertSame(['limit' => '10', 'order' => '1'], $request->getParam('named'));
            $this->assertSame(['not:configured', 'pass'], $request->getParam('pass'));
            $this->assertSame(['queryParam' => 'queryParamValue', 'limit' => '10', 'order' => '1'], $request->getQueryParams('query'));

            return $handler->handle($request);
        });

        $this->builder->scope('/', function (RouteBuilder $routes): void {
            $routes->applyMiddleware('test');
            $routes->connect('/{controller}/{action}/*');
        });
        $this->builder->fallbacks();

        $request = ServerRequestFactory::fromGlobals(
            [
                'REQUEST_METHOD' => 'GET',
                'REQUEST_URI' => '/articles/index/limit:10/order:1/not:configured/pass',
            ],
            [
                'queryParam' => 'queryParamValue',
            ]
        );

        $handler = new TestRequestHandler();
        $middleware = new RoutingMiddleware($this->app());
        $middleware->process($request, $handler);
    }

    /**
     * Create a stub application for testing.
     *
     * @param callable|null $handleCallback Callback for "handle" method.
     */
    protected function app($handleCallback = null): HttpApplicationInterface
    {
        $mock = $this->createMock(Application::class);
        $mock->method('routes')
            ->will($this->returnCallback(function (RouteBuilder $routes) {
                return $routes;
            }));

        if ($handleCallback) {
            $mock->method('handle')
                ->will($this->returnCallback($handleCallback));
        }

        return $mock;
    }
}
