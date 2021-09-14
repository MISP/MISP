<?php

declare(strict_types=1);

namespace Helper\Module;

use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

// here you can define custom actions
// all public methods declared in helper class will be available in $I

final class Api extends \Codeception\Module\REST
{
    public function getMethod(): string
    {
        $request = $this->connectionModule->client->getInternalRequest();
        return strtolower($request->getMethod());
    }

    public function getUrl(): string
    {
        $request = $this->connectionModule->client->getInternalRequest();
        return $request->getUri();
    }

    public function getRequest(): RequestInterface
    {
        $request = $this->connectionModule->client->getInternalRequest();

        return new Request($request->getMethod(), $request->getUri(), $this->connectionModule->headers, $request->getContent());
    }


    public function getResponse(): ResponseInterface
    {
        $response = $this->connectionModule->client->getInternalResponse();

        return new Response($response->getStatusCode(), $response->getHeaders(), $response->getContent());
    }
}
