<?php

use Elasticsearch\ClientBuilder;

class ElasticSearchClient
{
    private $__settings = false;
    private $__client = false;

    private function __getSetSettings()
    {
        $settings = array(
                'enabled' => false,
                'connection_string' => 'http://localhost',
        );

        foreach ($settings as $key => $setting) {
            $temp = Configure::read('Plugin.ElasticSearch_' . $key);
            if ($temp) {
                $settings[$key] = $temp;
            }
        }
        return $settings;
    }

    public function initTool()
    {
        $settings = $this->__getSetSettings();
        $hosts = explode(",", $settings["connection_string"]);
        $client = ClientBuilder::create()
                    ->setHosts($hosts)
                    ->build();
        $this->__client = $client;
        $this->__settings = $settings;
        return $client;
    }

    public function pushDocument($index, $document_type, $document)
    {
        // Format timestamp
        $time = strftime("%Y-%m-%d %H:%M:%S", strtotime($document["Log"]["created"]));
        $document["Log"]["created"] = $time;
        $params = array(
            'index' => $index,
            'type' => $document_type,
            'body' => $document
        );

        $this->__client->index($params);
    }
}
