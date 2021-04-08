<?php

namespace Helper\Module;

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
        $this->validator = (new \League\OpenAPIValidation\PSR7\ValidatorBuilder)->fromYamlFile($this->config['openapi']);
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
        $address = new \League\OpenAPIValidation\PSR7\OperationAddress($this->restModule->getUrl(), $this->restModule->getMethod());
        $responseValidator = $this->validator->getResponseValidator();
        $responseValidator->validate($address, $this->restModule->getResponse());
    }
}
