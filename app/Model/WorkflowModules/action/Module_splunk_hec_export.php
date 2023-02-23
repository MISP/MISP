<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

App::uses('SyncTool', 'Tools');
App::uses('JsonTool', 'Tools');

class Module_splunk_hec_export extends WorkflowBaseActionModule
{
    public $id = 'splunk-hec-export';
    public $name = 'Splunk HEC export';
    public $version = '0.1';
    public $description = 'Export Event Data to Splunk HTTP Event Collector';
    public $icon_path = 'Splunk.png';
    public $inputs = 1;
    public $outputs = 0;
    public $support_filters = false;
    public $params = [];

    private $timeout = false;
    private $Event;

    public function __construct()
    {
        parent::__construct();
        $this->params = [
            [
                'id' => 'url',
                'label' => __('HEC URL'),
                'type' => 'input',
                'placeholder' => 'https://splunk:8088/services/collector/event',
            ],
            [
                'id' => 'verify_tls',
                'label' => __('Verify HTTPS Certificate'),
                'type' => 'select',
                'options' => [
                    'true' => __('True'),
                    'false' => __('False'),
                ],
                'default' => 'true',
            ],
            [
                'id' => 'hec_token',
                'label' => __('HEC Token'),
                'type' => 'select',
                'type' => 'input',
                'placeholder' => '00000000-0000-0000-000000000000'
            ],
            [
                'id' => 'event_per_attribute',
                'label' => __('Create one Splunk Event per Attribute'),
                'type' => 'select',
                'options' => [
                    'true' => __('True'),
                    'false' => __('False'),
                ],
                'default' => 'false',
            ],
            [
                'id' => 'data_extraction_model',
                'label' => __('Data extraction model (JSON)'),
                'type' => 'textarea',
                'default' => '',
                'placeholder' => '{ "EventInfo": "Event.info", "AttributeValue": "Event.Attribute.{n}.value"}',
            ],
        ];
    }

    public function diagnostic(): array
    {
        $errors = array_merge(parent::diagnostic(), []);
        if (empty(Configure::read('Security.rest_client_enable_arbitrary_urls'))) {
            $errors = $this->addNotification(
                $errors,
                'error',
                __('`rest_client_enable_arbitrary_urls` is turned off.'),
                __('The module will not send any request as long as `Security.rest_client_enable_arbitrary_urls` is turned off.'),
                [
                    __('This is a security measure to ensure a site-admin do not send arbitrary request to internal services')
                ],
                true,
                true
            );
        }
        return $errors;
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors = []): bool
    {
        parent::exec($node, $roamingData, $errors);
        if (empty(Configure::read('Security.rest_client_enable_arbitrary_urls'))) {
            $errors[] = __('`Security.rest_client_enable_arbitrary_urls` is turned off');
            return false;
        }
        $params = $this->getParamsWithValues($node);
        if (empty($params['url']['value'])) {
            $errors[] = __('URL not provided.');
            return false;
        }

        $rData = $roamingData->getData();

        //$path = $params['data_extraction_path']['value'];
        //$extracted = !empty($params['data_extraction_path']['value']) ? $this->extractData($rData, $path) : $rData;

        $event_without_attributes = $rData['Event'];
        unset($event_without_attributes['Attribute']);
        unset($event_without_attributes['_AttributeFlattened']);

        $splunk_events = [];
        if ($params['event_per_attribute']['value'] == 'true') {
            foreach ($rData['Event']['Attribute'] as $attribute) {
                array_push($splunk_events, [
                        'Attribute' => $attribute,
                        'Event' => $event_without_attributes
                ]);
            }
        } else {
            array_push($splunk_events, $rData);
        }

	if (!empty($params['data_extraction_model']['value'])) {
                $data_extraction_model = JsonTool::decode($params['data_extraction_model']['value']);
		$extracted_events = [];
		foreach ($splunk_events as $splunk_event) {
			$event = array();
			foreach ($data_extraction_model as $field => $path) {
				$field_data = $this->extractData($splunk_event, $path);
				$event[$field] = count($field_data) == 1 ? $field_data[0] : $field_data; // unpack if only one element
			}         
			array_push($extracted_events, $event);
		}
		$splunk_events = $extracted_events;
	}

        foreach ($splunk_events as $splunk_event) {
            try {
                $response = $this->doRequest($params['url']['value'], $params['hec_token']['value'], $params['verify_tls']['value'], $splunk_event);
                if (!$response->isOk()) {
                    if ($response->code === 403 || $response->code === 401) {
                        $errors[] = __('Authentication failed.');
                        return false;
                    }
                    $errors[] = __('Something went wrong with the request or the remote side is having issues. Body returned: %s', $response->body);
                    return false;
                }
            } catch (SocketException $e) {
                $errors[] = __('Something went wrong while sending the request. Error returned: %s', $e->getMessage());
                return false;
            } catch (Exception $e) {
                $errors[] = __('Something went wrong. Error returned: %s', $e->getMessage());
                return false;
            }
        }
        return true;
    }

    protected function doRequest($url, $hec_token, $verify_tls, $data)
    {
        $this->Event = ClassRegistry::init('Event'); // We just need a model to use AppModel functions
        $version = implode('.', $this->Event->checkMISPVersion());
        $commit = $this->Event->checkMIPSCommit();

        $request = [
            'header' => [
                'Authorization' => 'Splunk ' . $hec_token,
            ]
        ];
        $syncTool = new SyncTool();

        $server = [];
        if ($verify_tls == 'false') {
            $server['Server'] = ['self_signed' => true];
        }

        $HttpSocket = $syncTool->setupHttpSocket($server, $this->timeout, 'Server');


        $HEC_Event = [
            'event' => $data,
        ];

        $response = $HttpSocket->post($url, JsonTool::encode($HEC_Event), $request);
        return $response;
    }
}
