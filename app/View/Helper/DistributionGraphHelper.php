<?php
App::uses('AppHelper', 'View/Helper');

class DistributionGraphHelper extends AppHelper
{
    private $__distributionData = [];

    /**
     * Get distribution graph data for a given event ID.
     * Caches result within the request to avoid redundant calculations.
     * 
     * @param int $id Event ID (-1 for global/index view)
     * @return array
     */
    public function getGraphData($id = -1)
    {
        if (isset($this->__distributionData[$id])) {
            return $this->__distributionData[$id];
        }

        $eventModel = ClassRegistry::init('Event');
        $serverModel = ClassRegistry::init('Server');

        $servers = $serverModel->find('column', array(
            'fields' => array('Server.name'),
        ));

        App::uses('DistributionGraphTool', 'Tools');
        $user = AuthComponent::user();
        if (!$user) {
            return [];
        }

        $grapher = new DistributionGraphTool($eventModel, $servers, $user);
        $json = $grapher->get_distributions_graph($id);

        array_walk_recursive($json, function (&$item, $key) {
            if (is_string($item) && !mb_detect_encoding($item, 'utf-8', true)) {
                $item = utf8_encode($item);
            }
        });

        $this->__distributionData[$id] = $json;
        return $json;
    }
}
