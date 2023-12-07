<?php

declare(strict_types=1);

namespace App\Test\Helper;

use Cake\Core\Configure;
use Cake\Http\Exception\NotImplementedException;
use Cake\Http\ServerRequest;
use Cake\Http\ServerRequestFactory;
use Cake\TestSuite\IntegrationTestTrait;
use League\OpenAPIValidation\PSR7\OperationAddress;

/**
 * Trait ControllerTestTrait
 *
 * @package App\Test\TestCase\Helper
 */
trait ControllerTestTrait
{
    use IntegrationTestTrait {
        IntegrationTestTrait::_sendRequest as _sendRequestOriginal;
    }

    /**
     * This method intercepts IntegrationTestTrait::_buildRequest()
     * and validates the response against the OpenAPI spec.
     *
     * @see \Cake\TestSuite\IntegrationTestTrait::_sendRequest()
     *
     * @param array|string $url The URL
     * @param string $method The HTTP method
     * @param array|string $data The request data.
     * @return void
     * @throws \PHPUnit\Exception|\Throwable
     */
    protected function _sendRequest($url, $method, $data = []): void
    {
        // somehow this is not set automatically in test environment
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
        $_SERVER['HTTP_USER_AGENT'] = 'CakePHP TestSuite';
        $_SERVER['REQUEST_METHOD'] = $method;
        $_SERVER['CONTENT_TYPE'] = 'text/html; charset=UTF-8';
        $_SERVER['HTTP_CONTENT_ENCODING'] = 'text/html; charset=UTF-8';

        $this->_sendRequestOriginal($url, $method, $data);
    }
}
