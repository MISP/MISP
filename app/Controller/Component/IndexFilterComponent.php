<?php

/**
 * Get filter parameters from index searches
 */

class IndexFilterComponent extends Component
{
    /** @var Controller */
    public $Controller;
    public $isRest = null;

    // Used for isApiFunction(), a check that returns true if the controller & action combo matches an action that is a non-xml and non-json automation method
    // This is used to allow authentication via headers for methods not covered by _isRest() - as that only checks for JSON and XML formats
    const AUTOMATION_ARRAY = array(
        'events' => array('csv', 'nids', 'hids', 'xml', 'restSearch', 'stix', 'updateGraph', 'downloadOpenIOCEvent'),
        'attributes' => array('text', 'downloadAttachment', 'returnAttributes', 'restSearch', 'rpz', 'bro'),
        'objects' => array('restSearch'),
    );

    public function initialize(Controller $controller)
    {
        $this->Controller = $controller;
    }

    // generic function to standardise on the collection of parameters. Accepts posted request objects, url params, named url params
    public function harvestParameters($paramArray, &$exception = [])
    {
        $request = $this->Controller->request;
        $data = [];
        if ($request->is('post')) {
            if (empty($request->data)) {
                $exception = $this->Controller->RestResponse->throwException(
                    400,
                    __('Either specify the search terms in the url, or POST a json with the filter parameters.'),
                    '/' . $request->params['controller'] . '/' . $this->Controller->action
                );
                return false;
            } else {
                if (isset($request->data['request'])) {
                    $data = $request->data['request'];
                } else {
                    $data = $request->data;
                }
            }
        }

        $data = $this->__massageData($data, $request, $paramArray);

        $this->Controller->set('passedArgs', json_encode($this->Controller->passedArgs));
        return $data;
    }

    private function __massageData($data, $request, $paramArray)
    {
        $data = array_filter($data, function($paramName) use ($paramArray) {
            return in_array($paramName, $paramArray);
        }, ARRAY_FILTER_USE_KEY);

        if (!empty($paramArray)) {
            foreach ($paramArray as $p) {
                if (isset($request->params['named'][$p])) {
                    $data[$p] = str_replace(';', ':', $request->params['named'][$p]);
                }
            }
        }
        foreach ($data as &$v) {
            if (is_string($v)) {
                $v = trim($v);
                if (strpos($v, '||')) {
                    $v = explode('||', $v);
                }
            }
        }
        unset($v);
        return $data;

    }

    public function isRest()
    {
        // This method is surprisingly slow and called many times for one request, so it make sense to cache the result.
        if ($this->isRest !== null) {
            return $this->isRest;
        }
        $api = $this->isApiFunction($this->Controller->request->params['controller'], $this->Controller->request->params['action']);
        if (isset($this->Controller->RequestHandler) && ($api || $this->isJson() || $this->Controller->RequestHandler->isXml() || $this->isCsv())) {
            $this->isRest = true;
            return true;
        } else {
            $this->isRest = false;
            return false;
        }
    }

    public function isJson()
    {
        return $this->Controller->request->header('Accept') === 'application/json' || $this->Controller->RequestHandler->prefers() === 'json';
    }

    public function isCsv()
    {
        return $this->Controller->request->header('Accept') === 'text/csv' || $this->Controller->RequestHandler->prefers() === 'csv';
    }

    public function isXml()
    {

    }

    /**
     * @param string $controller
     * @param string $action
     * @return bool
     */
    public function isApiFunction($controller, $action)
    {
        return isset(self::AUTOMATION_ARRAY[$controller]) && in_array($action, self::AUTOMATION_ARRAY[$controller], true);
    }
}
