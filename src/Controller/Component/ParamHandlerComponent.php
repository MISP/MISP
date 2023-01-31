<?php

namespace App\Controller\Component;

use Cake\Controller\Component;
use Cake\Core\Configure;
use Cake\Http\Exception\MethodNotAllowedException;

class ParamHandlerComponent extends Component
{
    public function initialize(array $config): void
    {
        $this->request = $config['request'];
    }

    /*
     *  Harvest parameters form a request
     *
     *  Requires the request object and a list of keys to filter as input
     *  Order of precedence:
     *  ordered uri components (/foo/bar/baz) > query strings (?foo=bar) > posted data (json body {"foo": "bar"})
     */
    public function harvestParams(array $filterList): array
    {
        $parsedParams = array();
        foreach ($filterList as $k => $filter) {
            $queryString = str_replace('.', '_', $filter);
            $queryString = str_replace(' ', '_', $queryString);
            if ($this->request->getQuery($queryString) !== null) {
                if (is_array($this->request->getQuery($queryString))) {
                    $parsedParams[$filter] = array_map('trim', $this->request->getQuery($queryString));
                } else {
                    $parsedParams[$filter] = trim($this->request->getQuery($queryString));
                }
                continue;
            }
            if (($this->request->is('post') || $this->request->is('put')) && $this->request->getData($filter) !== null) {
                $parsedParams[$filter] = trim($this->request->getData($filter));
            }
        }
        return $parsedParams;
    }

    public function isRest()
    {
        // This method is surprisingly slow and called many times for one request, so it make sense to cache the result.
        if ($this->isRest !== null) {
            return $this->isRest;
        }
        if ($this->request->is('json')) {
            if (!empty((string)$this->request->getBody()) && !is_array($this->request->getParsedBody())) {
                throw new MethodNotAllowedException('Invalid JSON input. Make sure that the JSON input is a correctly formatted JSON string. This request has been blocked to avoid an unfiltered request.');
            }
            $this->isRest = true;
            return true;
        } else {
            $this->isRest = false;
            return false;
        }
    }

    public function isJson($data)
    {
        return (json_decode($data) != null) ? true : false;
    }

    public function isAjax()
    {
        if ($this->isAjax !== null) {
            return $this->isAjax;
        }
        $this->isAjax = $this->request->is('ajax');
        return $this->isAjax;
    }
}
