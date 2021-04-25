<?php
class DevShell extends AppShell {

    public $uses = [];

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
}
