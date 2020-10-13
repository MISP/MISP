<?php


class DeprecationComponent extends Component
{
    public $redis = false;

    /*
     *  Deprecated endpoints
     *  - simple controller->action structure
     *  - each endpoint can be set to to a deprecation warning message or false
     */
    public $deprecatedEndpoints = false;

    public function initialize(Controller $controller) {
        $this->deprecatedEndpoints = array(
            'attributes' => array(
                'rpz' => __('Use /attributes/restSearch to export RPZ rules.'),
                'text' => __('Use /attributes/restSearch to export flat indicator lists.')
            ),
            'events' => array(
                'addIOC' => __('Use MISP modules to import in OpenIOC format.'),
                'csv' => __('Use /events/restSearch to export in CSV format.'),
                'export' => __('Use the REST client to refine your search conditions and export in any of the given formats with much more control.'),
                'hids' => __('Use /events/restSearch to export hashes.'),
                'nids' => __('Use /events/restSearch to export in the various NIDS formats.'),
                'stix' => __('Use /events/restSearch to export in STIX format.'),
                'stix2' => __('Use /events/restSearch to export in STIX2 format.'),
                'xml' => __('Use /events/restSearch to export in XML format. It is highly recommended to use JSON whenever possible.')
            ),
            'posts' => array(
                'add' => false,
                'index' => false
            ),
            'templates' => array(
                'add' => false,
                'populateEventFromTemplate' => false
            ),
            'allowedlists' => array(
                'admin_add' => false
            )
        );
    }

    public function checkDeprecation($controller, $action, $model, $user_id)
    {
        if (isset($this->deprecatedEndpoints[$controller][$action])) {
            $this->__logDeprecatedAccess($controller, $action, $model, $user_id);
            if ($this->deprecatedEndpoints[$controller][$action]) {
                return $this->deprecatedEndpoints[$controller][$action];
            }
        }
        return false;
    }

    private function __logDeprecatedAccess($controller, $action, $model, $user_id)
    {
        $this->redis = $model->setupRedis();
        if ($this->redis) {
            @$this->redis->hincrby(
                'misp:deprecation',
                sprintf(
                    '%s:%s:%s',
                    $controller,
                    $action,
                    $user_id
                ),
                1
            );
            $result = $this->redis->hGetAll('misp:deprecation');
        }
        return false;
    }

    public function getDeprecatedAccessList($model)
    {
        $this->redis = $model->setupRedis();
        if ($this->redis) {
            $rearranged = array();
            @$result = $this->redis->hGetAll('misp:deprecation');
            if (!empty($result)) {
                foreach ($result as $key => $value) {
                    $key_components = explode(':', $key);
                    $rearranged[$key_components[0]][$key_components[1]][$key_components[2]] = (int)$value;
                    if (empty($rearranged[$key_components[0]][$key_components[1]]['total'])) {
                        $rearranged[$key_components[0]][$key_components[1]]['total'] = (int)$value;
                    } else {
                        $rearranged[$key_components[0]][$key_components[1]]['total'] += (int)$value;
                    }
                }
            }
        }
        return $rearranged;
    }
}
