<?php
// Loaded from CRUDComponentEditTest::setUp(), which runs each test in its own process.

if (!function_exists('__')) {
    function __($singular, $args = null)
    {
        return vsprintf($singular, array_slice(func_get_args(), 1));
    }
}

class Component
{
}

class Controller
{
}

class NotFoundException extends RuntimeException
{
}

class CrudStubRequest
{
    public $data = [];
    public $method = 'put';

    public function is($type)
    {
        return $type === $this->method;
    }
}

class CrudStubModel
{
    public $stored;
    public $saved;

    public function __construct(array $stored)
    {
        $this->stored = $stored;
    }

    public function find($type, $query)
    {
        return $this->stored;
    }

    public function save($data)
    {
        $this->saved = $data;
        return $data;
    }
}

class CrudStubIndexFilter
{
    public function isRest()
    {
        return true;
    }
}

class CrudStubRestResponse
{
    public function viewData($data, $format)
    {
        return $data;
    }
}

class CrudStubController extends Controller
{
    public $modelClass = 'Collection';
    public $request;
    public $IndexFilter;
    public $RestResponse;
    public $restResponsePayload;
    public $Collection;

    public function __construct(CrudStubModel $model, array $input)
    {
        $this->Collection = $model;
        $this->request = new CrudStubRequest();
        $this->request->data = $input;
        $this->IndexFilter = new CrudStubIndexFilter();
        $this->RestResponse = new CrudStubRestResponse();
    }

    public function set($key, $value = null)
    {
    }
}

require_once __DIR__ . '/../Controller/Component/CRUDComponent.php';
