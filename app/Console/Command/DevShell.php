<?php

App::uses('ComponentCollection', 'Controller');
App::uses('RestSearchComponent', 'Controller/Component');

class DevShell extends AppShell {

    public $uses = ['MispAttribute', 'Event', 'Object', 'GalaxyCluster', 'Sighting'];

    public function cleanFeedDefault() {
        $this->out(__('Massaging the feed metadata file.'));
        $data = file_get_contents(APP . 'files/feed-metadata/defaults.json');
        if (empty($data)) {
            $this->stdout->styles('error');
            $this->out(__('Could not read the defaults.json file at %s. Exiting', APP . 'files/feed-metadata/defaults.json'));
        } else {
            $data = json_decode($data, true);
            $validFields = [
                'Feed' => [
                    'name', 'provider', 'url', 'rules', 'enabled', 'distribution',
                    'default', 'source_format', 'fixed_event', 'delta_merge',
                    'publish', 'override_ids', 'settings', 'input_source',
                    'delete_local_file', 'lookup_visible'
                ],
                'Tag' => [
                    'name', 'colour', 'exportable', 'hide_tag'
                ]
            ];
            foreach ($data as $k => $feedData) {
                $temp = [];
                foreach ($validFields as $scope => $fieldNames) {
                    foreach ($fieldNames as $fieldName) {
                        if (isset($feedData[$scope][$fieldName])) {
                            $temp[$scope][$fieldName] = $feedData[$scope][$fieldName];
                        }
                    }
                }
                $data[$k] = $temp;
            }
            if (!empty($data)) {
                file_put_contents(APP . 'files/feed-metadata/defaults.json', json_encode($data, JSON_PRETTY_PRINT));
                $this->out(__(
                    'Done. The feed definitions contain %s feeds and can be found at %s.',
                    count($data),
                    APP . 'files/feed-metadata/defaults.json'
                ));
            } else {
                $this->stdout->styles('error');
                $this->out(__('Something went wrong.'));
            }
        }
    }

    public function generateSearchParams()
    {
        $fetchFunctionName = [
            'Attribute' => 'fetchAttributes',
            'Event' => 'fetchEvents',
            'Object' => 'fetchObjects',
            'Sighting' => 'fetchSightings',
            'GalaxyCluster' => 'fetchGalaxyClusters'
        ];
        $collection = new ComponentCollection();
        $this->RestSearchComponent = $collection->load('RestSearch');
        $paramArray = $this->RestSearchComponent->paramArray;
        foreach ($paramArray as $scope => $params) {
            if (!empty($this->$scope->possibleOptions)) {
                $paramArray[$scope] = array_values(array_unique(array_merge($paramArray[$scope], $this->$scope->possibleOptions)));
            } else {
                $fileName = $scope === 'Object' ? 'MispObject' : $scope;
                $code = file_get_contents(APP . 'Model/' . $fileName . '.php');
                $code = explode("\n", $code);
                $start = false;
                $end = false;
                $analyzedBlock = [];
                foreach ($code as $lineNumber => $line) {
                    if (strpos($line, 'public function ' . $fetchFunctionName[$scope] . '(') !== false) {
                        $start = $lineNumber;
                    }
                    if ($start) {
                        if ($lineNumber !== $start && strpos($line, 'public function') !== false) {
                            $end = $lineNumber - 1;
                            break;
                        }
                        $analyzedBlock[] = $line;
                    }
                }
                $analyzedBlock = implode("\n", $analyzedBlock);
                $foundParams = [];
                preg_match_all('/\$options\[\'([^\']+)/i', $analyzedBlock, $foundParams);
                $foundParams = $foundParams[1];
                foreach ($foundParams as $k => $v) {
                    if (in_array(strtolower($v), ['contain', 'fields', 'conditions', 'order', 'joins', 'group', 'limit', 'page', 'recursive', 'callbacks'])) {
                        unset($foundParams[$k]);
                    }
                }
                $paramArray[$scope] = array_values(array_unique(array_merge($paramArray[$scope], $foundParams)));
            }
        }
        foreach ($paramArray as $scope => $fields) {
            echo "'" . $scope ."' => [" . PHP_EOL . "    '";
            echo implode("'," . PHP_EOL . "    '", $fields) . "'" . PHP_EOL;
            echo "]," . PHP_EOL;
        }
    }
}
