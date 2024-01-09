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
 * Trait ApiTestTrait
 *
 * @package App\Test\TestCase\Helper
 */
trait ApiTestTrait
{
    use IntegrationTestTrait {
        IntegrationTestTrait::_buildRequest as _buildRequestOriginal;
        IntegrationTestTrait::_sendRequest as _sendRequestOriginal;
    }

    /** @var string */
    protected $_authToken = '';

    /** @var ValidatorBuilder */
    private $_validator;

    /** @var RequestValidator */
    private $_requestValidator;

    /** @var ResponseValidator */
    private $_responseValidator;

    /** @var ServerRequest */
    protected $_psrRequest;

    /** @var boolean */
    protected $_skipOpenApiValidations = false;

    public function setUp(): void
    {
        parent::setUp();
        $this->initializeOpenApiValidator();
    }

    public function setAuthToken(string $authToken): void
    {
        $this->_authToken = $authToken;

        // somehow this is not set automatically in test environment
        $_SERVER['HTTP_AUTHORIZATION'] = $authToken;

        $this->configRequest(
            [
                'headers' => [
                    'Accept' => 'application/json',
                    'Authorization' => $this->_authToken,
                    'Content-Type' => 'application/json'
                ]
            ]
        );
    }

    /**
     * Skip OpenAPI validations.
     *
     * @return void
     */
    public function skipOpenApiValidations(): void
    {
        $this->_skipOpenApiValidations = true;
    }

    public function assertResponseContainsArray(array $expected): void
    {
        $responseArray = json_decode((string)$this->_response->getBody(), true);
        throw new NotImplementedException('TODO: see codeception seeResponseContainsJson()');
    }

    /**
     * Load OpenAPI specification validator
     *
     * @return void
     */
    public function initializeOpenApiValidator(): void
    {
        if (!$this->_skipOpenApiValidations) {
            $this->_validator =  Configure::read('App.OpenAPIValidator');
            if ($this->_validator === null) {
                throw new \Exception('OpenAPI validator is not configured');
            }
        }
    }

    /**
     * Validates the API request against the OpenAPI spec
     *
     * @return void
     */
    public function assertRequestMatchesOpenApiSpec(): void
    {
        $this->_validator->getRequestValidator()->validate($this->_psrRequest);
    }

    /**
     * Validates the API response against the OpenAPI spec
     *
     * @param string $path The path to the API endpoint
     * @param string $method The HTTP method used to call the endpoint
     * @return void
     */
    public function assertResponseMatchesOpenApiSpec(string $endpoint, string $method = 'get'): void
    {
        $address = new OperationAddress($endpoint, $method);
        $this->_validator->getResponseValidator()->validate($address, $this->_response);
    }

    /**
     * Validates a record exists in the database
     *
     * @param string $table The table name
     * @param array $conditions The conditions to check
     * @return void
     * @throws \Exception
     * @throws \Cake\Datasource\Exception\RecordNotFoundException
     *
     * @see https://book.cakephp.org/4/en/orm-query-builder.html
     */
    public function assertDbRecordExists(string $table, array $conditions): void
    {
        $record = $this->getTableLocator()->get($table)->find()->where($conditions)->first();
        if (!$record) {
            throw new \PHPUnit\Framework\AssertionFailedError("Record not found in table '$table' with conditions: " . json_encode($conditions));
        }
        $this->assertNotEmpty($record);
    }

    /**
     * Validates a record do not exists in the database
     *
     * @param string $table The table name
     * @param array $conditions The conditions to check
     * @return void
     * @throws \Exception
     * @throws \Cake\Datasource\Exception\RecordNotFoundException
     *
     * @see https://book.cakephp.org/4/en/orm-query-builder.html
     */
    public function assertDbRecordNotExists(string $table, array $conditions): void
    {
        $record = $this->getTableLocator()->get($table)->find()->where($conditions)->first();
        if ($record) {
            throw new \PHPUnit\Framework\AssertionFailedError("Record found in table '$table' with conditions: " . json_encode($conditions));
        }
        $this->assertEmpty($record);
    }

    /**
     * Parses the response body and returns the decoded JSON
     *
     * @return array
     * @throws \Exception
     */
    public function getJsonResponseAsArray(): array
    {
        if ($this->_response->getHeaders()['Content-Type'][0] !== 'application/json') {
            throw new \Exception('The response is not a JSON response');
        }

        return json_decode((string)$this->_response->getBody(), true);
    }

    /**
     * Gets a database records as an array
     *
     * @param string $table The table name
     * @param array $conditions The conditions to check
     * @return array
     * @throws \Cake\Datasource\Exception\RecordNotFoundException
     */
    public function getRecordFromDb(string $table, array $conditions): array
    {
        return $this->getTableLocator()->get($table)->find()->where($conditions)->first()->toArray();
    }

    /**
     * This method intercepts IntegrationTestTrait::_buildRequest()
     * in the quest to get a PSR-7 request object and saves it for
     * later inspection, also validates it against the OpenAPI spec.
     * @see \Cake\TestSuite\IntegrationTestTrait::_buildRequest()
     *
     * @param string $url The URL
     * @param string $method The HTTP method
     * @param array|string $data The request data.
     * @return array The request context
     */
    protected function _buildRequest(string $url, $method, $data = []): array
    {
        $spec = $this->_buildRequestOriginal($url, $method, $data);

        $this->_psrRequest = $this->_createPsr7RequestFromSpec($spec);

        // Validate request against OpenAPI spec
        if (!$this->_skipOpenApiValidations) {
            try {
                $this->assertRequestMatchesOpenApiSpec();
            } catch (\Exception $exception) {
                $this->fail($exception->getMessage());
            }
        } else {
            $this->addWarning(
                sprintf(
                    'OpenAPI spec validations skipped for request [%s]%s.',
                    $this->_psrRequest->getMethod(),
                    $this->_psrRequest->getPath()
                )
            );
        }

        return $spec;
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
        // Adding Content-Type: application/json $this->configRequest() prevents this from happening somehow
        if (
            in_array($method, ['POST', 'PATCH', 'PUT'])
            && $this->_request['headers']['Content-Type'] === 'application/json'
        ) {
            $data = json_encode($data);
        }

        // somehow this is not set automatically in test environment
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
        $_SERVER['HTTP_USER_AGENT'] = 'CakePHP TestSuite';
        $_SERVER['REQUEST_METHOD'] = $method;
        $_SERVER['CONTENT_TYPE'] = $this->_request['headers']['Content-Type'];
        $_SERVER['HTTP_CONTENT_ENCODING'] = $this->_request['headers']['Content-Type'];

        $this->_sendRequestOriginal($url, $method, $data);

        // Validate response against OpenAPI spec
        if (!$this->_skipOpenApiValidations) {
            $this->assertResponseMatchesOpenApiSpec(
                $this->_psrRequest->getPath(),
                strtolower($this->_psrRequest->getMethod())
            );
        } else {
            $this->addWarning(
                sprintf(
                    'OpenAPI spec validations skipped for response of [%s]%s.',
                    $this->_psrRequest->getMethod(),
                    $this->_psrRequest->getPath()
                )
            );
        }
    }

    /**
     * Create a PSR-7 request from the request spec.
     * @see \Cake\TestSuite\MiddlewareDispatcher::_createRequest()
     *
     * @param array<string, mixed> $spec The request spec.
     * @return \Cake\Http\ServerRequest
     */
    private function _createPsr7RequestFromSpec(array $spec): ServerRequest
    {
        if (isset($spec['input'])) {
            $spec['post'] = [];
            $spec['environment']['CAKEPHP_INPUT'] = $spec['input'];
        }
        $environment = array_merge(
            array_merge($_SERVER, ['REQUEST_URI' => $spec['url']]),
            $spec['environment']
        );
        if (strpos($environment['PHP_SELF'], 'phpunit') !== false) {
            $environment['PHP_SELF'] = '/';
        }
        return ServerRequestFactory::fromGlobals(
            $environment,
            $spec['query'],
            $spec['post'],
            $spec['cookies'],
            $spec['files']
        );
    }
}
