<?php

declare(strict_types=1);

namespace App\Test\Helper\TestApp;

use Cake\Http\Response;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

class TestRequestHandler implements RequestHandlerInterface
{
    public $callable;

    public $called = false;

    public function __construct(?callable $callable = null)
    {
        $this->callable = $callable ?: function ($request) {
            $this->called = true;

            return new Response();
        };
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        return ($this->callable)($request);
    }
}
