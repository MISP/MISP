<?php
App::uses('AppModel', 'Model');
App::uses('JsonTool', 'Tools');
App::uses('EncryptedValue', 'Tools');

class Module extends AppModel
{
    public $useTable = false;

    // private
    const VALID_TYPES = array(
        'Enrichment' => array('hover', 'expansion'),
        'Import' => array('import'),
        'Export' => array('export'),
        'Action' => array('action'),
        'Cortex' => array('cortex'),
        'AI' => array('ai')
    );

    // private
    const TYPE_TO_FAMILY = array(
        'Import' => 'Import',
        'Export' => 'Export',
        'Action' => 'Action',
        'hover' => 'Enrichment',
        'expansion' => 'Enrichment',
        'Cortex' => 'Cortex',
        'AI' => 'AI'
    );

    /**
     * The single hard-wired module of the AI family. It is never discovered
     * through /modules for gating: Plugin.AI_services_enable is the switch.
     */
    const AI_MODULE_NAME = 'ai_connector';

    /** The use-cases the AI module accepts (`use_case` of a request). */
    const AI_USE_CASES = ['summarization_on_event', 'summarization_on_eventReport', 'tag_suggest'];

    /**
     * The Plugin.AI_* settings sent to the module as `params`, listed by the
     * module's own config names (the setting name without the `AI_` prefix).
     */
    const AI_PARAM_SETTINGS = ['openai_api_base', 'api_key', 'model_id', 'temperature', 'request_timeout', 'suggest_limit', 'suggest_min_score'];

    const CONFIG_TYPES = array(
        'IP' => array(
            'validation' => 'validateIPField',
            'field' => 'text',
            'class' => 'input-xxlarge'
        ),
        'String' => array(
            'validation' => 'validateStringField',
            'field' => 'text',
            'class' => 'input-xxlarge'
        ),
        'Integer' => array(
            'validation' => 'validateIntegerField',
            'field' => 'number',
        ),
        'Boolean' => array(
            'validation' => 'validateBooleanField',
            'field' => 'checkbox'
        ),
        'Select' => array(
            'validation' => 'validateSelectField',
            'field' => 'select'
        )
    );

    private $httpSocket = [];

    public function validateIPField($value)
    {
        if (!filter_var($value, FILTER_VALIDATE_IP) === false) {
            return 'Value is not a valid IP.';
        }
        return true;
    }

    public function validateStringField($value)
    {
        if (!empty($value)) {
            return true;
        }
        return 'Field cannot be empty.';
    }

    public function validateIntegerField($value)
    {
        if (is_numeric($value) && is_int(intval($value))) {
            return true;
        }
        return 'Value is not an integer.';
    }

    public function validateBooleanField($value)
    {
        if ($value == true || $value == false) {
            return true;
        }
        return 'Value has to be a boolean.';
    }

    public function validateSelectField($value)
    {
        return true;
    }

    /**
     * @param string $moduleFamily
     * @param bool $throwException
     * @return array[]|string
     * @throws JsonException
     */
    public function getModules($moduleFamily = 'Enrichment', $throwException = false)
    {
        try {
            // Wait just one second to not block loading pages when modules are not reachable
            return $this->sendRequest('/modules', 1, null, $moduleFamily);
        } catch (Exception $e) {
            if ($throwException) {
                throw $e;
            }
            return 'Module service not reachable.';
        }
    }

    public function getEnabledModules($user, $type = false, $moduleFamily = 'Enrichment')
    {
        $modules = $this->getModules($moduleFamily);
        if (is_array($modules)) {
            foreach ($modules as $k => $module) {
                if (!Configure::read('Plugin.' . $moduleFamily . '_' . $module['name'] . '_enabled') || ($type && !in_array(strtolower($type), $module['meta']['module-type']))) {
                    unset($modules[$k]);
                    continue;
                }
                if (!$this->canUse($user, $moduleFamily, $module)) {
                    unset($modules[$k]);
                }
            }
        } else {
            return 'The modules system reports that it found no suitable modules.';
        }
        if (empty($modules)) {
            return [];
        }
        $output = ['modules' => array_values($modules)];
        foreach ($modules as $temp) {
            if (isset($temp['meta']['module-type']) && in_array('import', $temp['meta']['module-type'])) {
                $output['Import'] = $temp['name'];
            } elseif (isset($temp['meta']['module-type']) && in_array('export', $temp['meta']['module-type'])) {
                $output['Export'] = $temp['name'];
            } elseif (isset($temp['meta']['module-type']) && in_array('action', $temp['meta']['module-type'])) {
                $output['Action'] = $temp['name'];
            } elseif (isset($temp['meta']['module-type']) && in_array('ai', $temp['meta']['module-type'])) {
                $output['AI'] = $temp['name'];
            } else {
                foreach ($temp['mispattributes']['input'] as $input) {
                    if (!isset($temp['meta']['module-type']) || (in_array('expansion', $temp['meta']['module-type']) || in_array('cortex', $temp['meta']['module-type']))) {
                        $output['types'][$input][] = $temp['name'];
                    }
                    if (isset($temp['meta']['module-type']) && in_array('hover', $temp['meta']['module-type'])) {
                        $output['hover_type'][$input][] = $temp['name'];
                    }
                }
            }
        }
        return $output;
    }

    /**
     * @param string $name
     * @param string $type
     * @param array|null $user If provided, enforce the per-organisation module
     *                         restriction (canUse), matching getEnabledModules().
     * @return array|string
     */
    public function getEnabledModule($name, $type, array $user = null)
    {
        if (!isset(self::TYPE_TO_FAMILY[$type])) {
            throw new InvalidArgumentException("Invalid type '$type'.");
        }
        $moduleFamily = self::TYPE_TO_FAMILY[$type];
        $modules = $this->getModules($moduleFamily);
        if (!Configure::read('Plugin.' . $moduleFamily . '_' . $name . '_enabled')) {
            return 'The requested module is not enabled.';
        }
        if (is_array($modules)) {
            foreach ($modules as $module) {
                if ($module['name'] == $name) {
                    if ($type && in_array(strtolower($type), $module['meta']['module-type'])) {
                        if ($user !== null && !$this->canUse($user, $moduleFamily, $module)) {
                            return 'The requested module is restricted.';
                        }
                        return $module;
                    } else {
                        return 'The requested module is not available for the requested action.';
                    }
                }
            }
        } else {
            return $modules;
        }
        return 'The modules system reports that it found no suitable modules.';
    }

    private function __getModuleServer($moduleFamily = 'Enrichment')
    {
        if (!Configure::read('Plugin.' . $moduleFamily . '_services_enable')) {
            return false;
        }

        $url = Configure::read('Plugin.' . $moduleFamily . '_services_url');
        $port = Configure::read('Plugin.' . $moduleFamily . '_services_port');

        if (empty($url) || empty($port)) {
            // Load default values
            $this->Server = ClassRegistry::init('Server');
            if (empty($url)) {
                $url = $this->Server->serverSettings['Plugin'][$moduleFamily . '_services_url']['value'];
            }
            if (empty($port)) {
                $port = $this->Server->serverSettings['Plugin'][$moduleFamily . '_services_port']['value'];
            }
        }

        return "$url:$port";
    }

    private function __prepareAndExecuteTrigger($postData, $triggerData=[]): bool
    {
        $this->Workflow = ClassRegistry::init('Workflow');
        $trigger_id = 'enrichment-before-query';
        $workflowErrors = [];
        $logging = [
            'model' => 'Workflow',
            'action' => 'execute_workflow',
            'id' => 0,
        ];
        if (!$this->Workflow->isTriggerCallable($trigger_id)) {
            return true;
        }
        if (empty($triggerData) && !empty($postData['attribute_uuid'])) {
            $this->User = ClassRegistry::init('User');
            $this->Attribute = ClassRegistry::init('MispAttribute');
            $user = $this->User->getAuthUser(Configure::read('CurrentUserId'), true);
            $options = [
                'conditions' => [
                    'Attribute.uuid' => $postData['attribute_uuid'],
                ],
                'includeAllTags' => true,
                'includeAttributeUuid' => true,
                'flatten' => true,
                'deleted' => [0, 1],
                'withAttachments' => true,
                'contain' => ['Event' => ['fields' => ['distribution', 'sharing_group_id']]],
            ];
            $attributes = $this->Attribute->fetchAttributes($user, $options);
            $triggerData = !empty($attributes) ? $attributes[0] : [];
            $logging['message'] = __('The workflow `%s` prevented attribute `%s` (from event `%s`) to query the module `%s`', $trigger_id, $postData['attribute_uuid'], $triggerData['Attribute']['event_id'], $postData['module']);
        } else if (empty($triggerData) && !empty($postData['event_id'])) {
            $this->Event = ClassRegistry::init('Event');
            $event = $this->Event->quickFetchEvent($postData['event_id']);
            $triggerData = $event;
            $logging['message'] = __('The workflow `%s` prevented event `%s` to query the module `%s`', $trigger_id, $postData['event_id'], $postData['module']);
        } else {
            if (isset($triggerData['Attribute'])) {
                $logging['message'] = __('The workflow `%s` prevented attribute `%s` (from event `%s`) to query the module `%s`',
                    $trigger_id,
                    $triggerData['Attribute']['id'] ?? $triggerData['Attribute'][0]['id'],
                    $triggerData['Attribute']['event_id'] ?? $triggerData['Attribute'][0]['event_id'],
                    $postData['module']
                );
            } else {
                $logging['message'] = __('The workflow `%s` prevented attribute `%s` (from event `%s`) to query the module `%s`', $trigger_id, $triggerData['Event']['Attribute'][0]['id'], $triggerData['Event']['id'], $postData['module']);
            }
        }
        if (empty($triggerData)) {
            return false;
        }
        $success = $this->executeTrigger($trigger_id, $triggerData, $workflowErrors, $logging);
        return !empty($success);
    }

    /**
     * Send request to `/query` module endpoint.
     *
     * @param array $postData
     * @param bool $hover
     * @param string $moduleFamily
     * @param bool $throwException
     * @return array|false
     * @throws JsonException
     */
    public function queryModuleServer(array $postData, $hover = false, $moduleFamily = 'Enrichment', $throwException = false, $triggerData=[], $skipTrigger=false)
    {
        if ($moduleFamily === 'Enrichment' && empty($skipTrigger)) {
            $triggerData['_module'] = $postData['module'];
            $success = $this->__prepareAndExecuteTrigger($postData, $triggerData);
            if (!$success) {
                $trigger_id = 'enrichment-before-query';
                return __('Trigger `%s` blocked enrichment', $trigger_id);
            }
        }
        if ($hover) {
            $timeout = Configure::read('Plugin.' . $moduleFamily . '_hover_timeout') ?: 5;
        } else {
            $timeout = Configure::read('Plugin.' . $moduleFamily . '_timeout') ?: 10;
        }
        if (!isset($postData['timeout'])) {
            $postData['timeout'] = (int) $timeout;
        }
        try {
            return $this->sendRequest('/query', $timeout, $postData, $moduleFamily);
        } catch (Exception $e) {
            if ($throwException) {
                throw $e;
            }
            $this->logException('Failed to query module ' . $moduleFamily, $e);
            return false;
        }
    }

    /**
     * Low-level way how to send request to module.
     *
     * @param string $uri
     * @param int $timeout
     * @param array|null $postData
     * @param string $moduleFamily
     * @return array
     * @throws HttpSocketJsonException
     * @throws Exception
     */
    public function sendRequest($uri, $timeout, $postData = null, $moduleFamily = 'Enrichment')
    {
        $serverUrl = $this->__getModuleServer($moduleFamily);
        if (!$serverUrl) {
            throw new Exception("Module type $moduleFamily is not enabled.");
        }

        $httpSocket = $this->initHttpSocket($moduleFamily, $timeout);

        $request = [];
        if ($moduleFamily === 'Cortex') {
            if (!empty(Configure::read('Plugin.' . $moduleFamily . '_authkey'))) {
                $request['header']['Authorization'] = 'Bearer ' . Configure::read('Plugin.' . $moduleFamily . '_authkey');
            }
        }
        if ($postData) {
            if (!is_array($postData)) {
                throw new InvalidArgumentException("Post data must be array, " . gettype($postData) . " given.");
            }
            $post = JsonTool::encode($postData);
            $request['header']['Content-Type'] = 'application/json';
            $response = $httpSocket->post($serverUrl . $uri, $post, $request);
        } else {
            $response = $httpSocket->get($serverUrl . $uri, false, $request);
        }
        if (!$response->isOk()) {
            $e = new HttpSocketHttpException($response, $serverUrl . $uri);
            throw new Exception("Failed to get response from `$moduleFamily` module", 0, $e);
        }
        return $response->json();
    }

    /**
     * @param string $moduleFamily
     * @return array
     * @throws JsonException
     */
    public function getModuleSettings($moduleFamily = 'Enrichment')
    {
        $modules = $this->getModules($moduleFamily);
        $result = array();
        if (is_array($modules)) {
            foreach ($modules as $module) {
                if (array_intersect(self::VALID_TYPES[$moduleFamily], $module['meta']['module-type'])) {
                    $moduleSettings = [
                        [
                            'name' => 'enabled',
                            'type' => 'boolean',
                            'description' => empty($module['meta']['description']) ? '' : $module['meta']['description']
                        ]
                    ];
                    if ($moduleFamily !== 'Action') {
                        $moduleSettings[] = [
                            'name' => 'restrict',
                            'type' => 'orgs',
                            'description' => __('Restrict the use of this module to an organisation.')
                        ];
                        if (isset($module['meta']['config'])) {
                            foreach ($module['meta']['config'] as $key => $value) {
                                if (is_array($value)) {
                                    $name = is_string($key) ? $key : $value['name'];
                                    $moduleSettings[] = [
                                        'name' => $name,
                                        'type' => $value['type'] ?? 'string',
                                        'description' => $value['description'] ?? null,
                                        'null' => $value['null'] ?? null,
                                        'test' => $value['test'] ?? null,
                                        'bigField' => $value['bigField'] ?? false,
                                        'cli_only' => $value['cli_only'] ?? false,
                                        'redacted' => $value['redacted'] ?? false
                                    ];
                                } else if (is_string($key)) {
                                    $moduleSettings[] = [
                                        'name' => $key,
                                        'type' => 'string',
                                        'description' => $value
                                    ];
                                } else {
                                    $moduleSettings[] = array('name' => $value, 'type' => 'string');
                                }
                            }
                        }
                    }
                    $result[$module['name']] = $moduleSettings;
                }
            }
        }
        return $result;
    }

    /**
     * @param array $user
     * @param string $moduleFamily
     * @param array $module
     * @return bool
     */
    public function canUse(array $user, $moduleFamily, array $module)
    {
        if ($user['Role']['perm_site_admin']) {
            return true;
        }

        $config = Configure::read('Plugin.' . $moduleFamily . '_' . $module['name'] . '_restrict');
        if (empty($config)) {
            return true;
        }
        if ($config == $user['org_id']) {
            return true;
        }

        return false;
    }

    /**
     * @param string $moduleFamily
     * @param int $timeout
     * @return HttpSocketExtended|CurlClient
     */
    private function initHttpSocket($moduleFamily, $timeout)
    {
        $unique = "$moduleFamily:$timeout";

        if (isset($this->httpSocket[$unique])) {
            return $this->httpSocket[$unique];
        }

        $httpSocketSetting = ['timeout' => $timeout];
        $sslSettings = ['ssl_verify_peer', 'ssl_verify_host', 'ssl_allow_self_signed', 'ssl_cafile'];
        foreach ($sslSettings as $sslSetting) {
            $value = Configure::read('Plugin.' . $moduleFamily . '_' . $sslSetting);
            if ($value && $value !== '') {
                $httpSocketSetting[$sslSetting] = $value;
            }
        }

        if (function_exists('curl_init')) {
            App::uses('CurlClient', 'Tools');
            $httpSocket = new CurlClient($httpSocketSetting);
        } else {
            App::uses('HttpSocketExtended', 'Tools');
            $httpSocket = new HttpSocketExtended($httpSocketSetting);
        }

        return $this->httpSocket[$unique] = $httpSocket;
    }

    /**
     * The `params` block of an AI request: the settings of AI_PARAM_SETTINGS,
     * un-prefixed. A setting without a value (null or the empty string) is
     * left out so the module's own configuration applies to it.
     *
     * @param callable $read function (string $name): mixed — the effective
     *        value of `Plugin.AI_<name>`, or null; injected to keep the
     *        builder free of Configure
     * @return array
     */
    public static function buildAiParams(callable $read)
    {
        $params = [];
        foreach (self::AI_PARAM_SETTINGS as $name) {
            $value = $read($name);
            if ($value === null || $value === '') {
                continue;
            }
            $params[$name] = $value;
        }
        return $params;
    }

    /**
     * The request envelope the AI module expects on POST /query.
     *
     * @param string $useCase one of AI_USE_CASES
     * @param array $data {"Event": ...} or {"EventReport": ...}
     * @param array $params see buildAiParams()
     * @param int $timeout seconds, the module's time budget for the request
     * @return array
     * @throws InvalidArgumentException on an unknown use-case
     */
    public static function buildAiRequest($useCase, array $data, array $params, $timeout)
    {
        if (!in_array($useCase, self::AI_USE_CASES, true)) {
            throw new InvalidArgumentException("Unknown AI use-case `$useCase`.");
        }
        return [
            'module' => self::AI_MODULE_NAME,
            'data' => $data,
            'use_case' => $useCase,
            'params' => $params,
            'timeout' => (int)$timeout,
        ];
    }

    /**
     * Effective value of a Plugin.AI_* setting: what is configured, else the
     * default of its definition, so that a request carries exactly what the
     * settings page shows. A value stored encrypted is decrypted.
     *
     * @param string $name setting name without the `AI_` prefix
     * @return mixed|null
     */
    public function aiSetting($name)
    {
        $value = Configure::read('Plugin.AI_' . $name);
        if ($value instanceof EncryptedValue) {
            $value = $value->decrypt();
        }
        if ($value !== null) {
            return $value;
        }
        $this->Server = ClassRegistry::init('Server');
        return $this->Server->serverSettings['Plugin']['AI_' . $name]['value'] ?? null;
    }

    /**
     * Query the AI module: POST /query on the AI family server with the
     * envelope of buildAiRequest(), and return the `results` block of its
     * answer. Access control is the caller's job (perm_ai_tools + event ACL).
     *
     * @param string $useCase one of AI_USE_CASES
     * @param array $data {"Event": ...} or {"EventReport": ...}
     * @param int|null $timeout seconds, default Plugin.AI_timeout
     * @return array the module's `results`, e.g. ['EventReport' => [...]] or ['Tag' => [...]]
     * @throws InvalidArgumentException on an unknown use-case
     * @throws Exception when the AI services are disabled or unreachable, the
     *         answer is not JSON, or the module answered with `error`
     */
    public function queryAI($useCase, array $data, $timeout = null)
    {
        if ($timeout === null) {
            $timeout = (int)$this->aiSetting('timeout') ?: 300;
        }
        $params = self::buildAiParams([$this, 'aiSetting']);
        $request = self::buildAiRequest($useCase, $data, $params, $timeout);
        $response = $this->sendRequest('/query', $timeout, $request, 'AI');
        if (!is_array($response)) {
            throw new Exception(__('The AI module returned an unreadable answer.'));
        }
        if (!empty($response['error'])) {
            $error = is_string($response['error']) ? $response['error'] : JsonTool::encode($response['error']);
            throw new Exception(__('The AI module reported an error: %s', $error));
        }
        return isset($response['results']) && is_array($response['results']) ? $response['results'] : [];
    }
}
