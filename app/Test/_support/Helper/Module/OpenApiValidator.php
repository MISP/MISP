<?php

namespace Helper\Module;

use \League\OpenAPIValidation\PSR7\ValidatorBuilder;
use \League\OpenAPIValidation\PSR7\OperationAddress;

final class OpenApiValidator extends \Codeception\Module implements \Codeception\Lib\Interfaces\DependsOnModule
{

    protected $requiredFields = ['openapi'];

    private $validator;

    private $restModule;

    public function _depends()
    {
        return ['\Helper\Module\Api' => 'Api module is a mandatory dependency of OpenApiValidator'];
    }

    public function _inject(\Helper\Module\Api $restModule)
    {
        $this->restModule = $restModule;
    }

    public function _initialize()
    {
        $this->validator = (new ValidatorBuilder)->fromYamlFile($this->config['openapi']);
    }

    /**
     * Validates the API request against the OpenAPI spec
     * 
     * @return void
     */
    public function validateRequest(): void
    {
        $requestValidator = $this->validator->getRequestValidator();
        $requestValidator->validate($this->restModule->getRequest());
    }

    /**
     * Validates the API response against the OpenAPI spec
     * 
     * @return void
     */
    public function validateResponse(): void
    {
        $address = new OperationAddress($this->restModule->getUrl(), $this->restModule->getMethod());
        $responseValidator = $this->validator->getResponseValidator();
        $responseValidator->validate($address, $this->restModule->getResponse());
    }
}
