<?php

/**
 * Get filter parameters from index searches
 */

class IndexFilterComponent extends Component
{
    private $__Controller = false;

    public function startup(Controller $controller) {
        $this->__Controller = $controller;
    }

    // generic function to standardise on the collection of parameters. Accepts posted request objects, url params, named url params
    public function harvestParameters($paramArray, &$exception = array())
    {
        $data = array();
        if (!empty($this->__Controller->request->is('post'))) {
            if (empty($this->__Controller->request->data)) {
                $exception = $this->__Controller->RestResponse->throwException(
                    400,
                    __('Either specify the search terms in the url, or POST a json with the filter parameters.'),
                    '/' . $this->__Controller->request->params['controller'] . '/' . $this->__Controller->action
                );
                return false;
            } else {
                if (isset($this->__Controller->request->data['request'])) {
                    $data = $this->__Controller->request->data['request'];
                } else {
                    $data = $this->__Controller->request->data;
                }
            }
        }
        if (!empty($paramArray)) {
            foreach ($paramArray as $p) {
                if (
                    isset($options['ordered_url_params'][$p]) &&
                    (!in_array(strtolower((string)$options['ordered_url_params'][$p]), array('null', '0', false, 'false', null)))
                ) {
                    $data[$p] = $options['ordered_url_params'][$p];
                    $data[$p] = str_replace(';', ':', $data[$p]);
                }
                if (isset($this->__Controller->params['named'][$p])) {
                    $data[$p] = str_replace(';', ':', $this->__Controller->params['named'][$p]);
                }
            }
        }
        foreach ($data as $k => $v) {
            if (!is_array($data[$k])) {
                $data[$k] = trim($data[$k]);
                if (strpos($data[$k], '||')) {
                    $data[$k] = explode('||', $data[$k]);
                }
            }
        }
        if (!empty($options['additional_delimiters'])) {
            if (!is_array($options['additional_delimiters'])) {
                $options['additional_delimiters'] = array($options['additional_delimiters']);
            }
            foreach ($data as $k => $v) {
                $found = false;
                foreach ($options['additional_delimiters'] as $delim) {
                    if (strpos($v, $delim) !== false) {
                        $found = true;
                    }
                }
                if ($found) {
                    $data[$k] = explode($options['additional_delimiters'][0], str_replace($options['additional_delimiters'], $options['additional_delimiters'][0], $v));
                    foreach ($data[$k] as $k2 => $value) {
                        $data[$k][$k2] = trim($data[$k][$k2]);
                    }
                }
            }
        }
        $this->__Controller->set('passedArgs', json_encode($this->__Controller->passedArgs, true));
        return $data;
    }

}
