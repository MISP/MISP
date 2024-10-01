<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

App::uses('SyncTool', 'Tools');
App::uses('JsonTool', 'Tools');

class Module_splunk_hec_export extends Module_webhook
{
    public $id = 'splunk-hec-export';
    public $name = 'Splunk HEC export';
    public $version = '0.2';
    public $description = 'Export Event Data to Splunk HTTP Event Collector. Due to the potential high amount of requests, it\'s recommanded to put this module after a `concurrent_task` logic module.';
    public $icon_path = 'Splunk.png';
    public $support_filters = false;
    public $expect_misp_core_format = true;
    public $params = [];
    public $outputs = 0;

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
                    '1' => __('True'),
                    '0' => __('False'),
                ],
                'default' => 1,
            ],
            [
                'id' => 'hec_token',
                'label' => __('HEC Token'),
                'type' => 'select',
                'type' => 'input',
                'placeholder' => '00000000-0000-0000-000000000000'
            ],
            [
                'id' => 'source_type',
                'label' => __('Source Type'),
                'type' => 'select',
                'type' => 'input',
            'default' => '',
                'placeholder' => 'misp:event'
            ],
            [
                'id' => 'event_per_attribute',
                'label' => __('Create one Splunk Event per Attribute'),
                'type' => 'select',
                'options' => [
                    '1' => __('True'),
                    '0' => __('False'),
                ],
                'default' => 0,
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

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors = []): bool
    {
        if (empty(Configure::read('Security.rest_client_enable_arbitrary_urls'))) {
            $errors[] = __('`Security.rest_client_enable_arbitrary_urls` is turned off');
            return false;
        }
        $rData = $roamingData->getData();
        $params = $this->getParamsWithValues($node, $rData);
        if (empty($params['url']['value'])) {
            $errors[] = __('URL not provided.');
            return false;
        }
        if (empty($params['hec_token']['value'])) {
            $errors[] = __('Authorization token not provided.');
            return false;
        }

        $event_without_attributes = $rData['Event'];
        unset($event_without_attributes['Attribute']);
        unset($event_without_attributes['_AttributeFlattened']);

        $splunk_events = [];
        if (!empty($params['event_per_attribute']['value'])) {
            foreach ($rData['Event']['Attribute'] as $attribute) {
                $splunk_events[] = [
                    'Attribute' => $attribute,
                    'Event' => $event_without_attributes
                ];
            }
        } else {
            $splunk_events[] = $rData;
        }

        if (!empty($params['data_extraction_model']['value'])) {
            $data_extraction_model = JsonTool::decode($params['data_extraction_model']['value']);
            $extracted_events = [];
            foreach ($splunk_events as $splunk_event) {
                $event = [];
                foreach ($data_extraction_model as $field => $path) {
                    $field_data = $this->extractData($splunk_event, $path);
                    $event[$field] = count($field_data) == 1 ? $field_data[0] : $field_data; // unpack if only one element
                }
                $extracted_events[] = $event;
            }
            $splunk_events = $extracted_events;
        }

        return $this->sendToSplunk($splunk_events, $params['hec_token']['value'], $params['url']['value'], $params['source_type']['value']);
    }

    protected function sendToSplunk(array $splunk_events, $token, $url, $source_type): bool
    {
        foreach ($splunk_events as $splunk_event) {
            try {
                $headers = [
                    'Authorization' => "Splunk {$token}",
                ];
                $serverConfig = [
                    'Server' => ['self_signed' => empty($params['verify_tls']['value'])]
                ];

                $hec_event = [
                    'event' => $splunk_event
                ];
                if (!empty($source_type)) {
                    $hec_event['sourcetype'] = $source_type;
                }

                $response = $this->doRequest(
                    $url,
                    'json',
                    $hec_event,
                    $headers,
                    'post',
                    $serverConfig
                );
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
}
