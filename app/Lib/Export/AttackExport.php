<?php

class AttackExport
{
    public $additional_params = array(
        'flatten' => 1,
        'includeEventTags' => 1,
        'includeGalaxy' => 1
    );

    public $non_restrictive_export = true;
    public $renderView = 'attack_view';

    private $__clusterCounts = array();
    private $__attackGalaxy = 'mitre-attack-pattern';
    private $__galaxy_id = 0;
    private $__galaxy_name = '';
    private $__GalaxyModel = null;
    private $__tabs = false;
    private $__matrixTags = false;
    private $__killChainOrders = false;
    private $__instanceUUID = false;
    private $__scope = 'Event';

    public function handler($data, $options = array())
    {
        if (empty($this->__GalaxyModel)) {
            $this->__GalaxyModel = ClassRegistry::init('Galaxy');
        }
        $this->__attackGalaxy = empty($options['filters']['attackGalaxy']) ? $this->__attackGalaxy : $options['filters']['attackGalaxy'];
        $temp = $this->__GalaxyModel->find('first', array(
                'recursive' => -1,
                'fields' => array('id', 'name'),
                'conditions' => array('Galaxy.type' => $this->__attackGalaxy, 'Galaxy.namespace !=' => 'deprecated'),
        ));
        if (empty($temp)) {
            return '';
        } else {
            $this->__galaxy_id = $temp['Galaxy']['id'];
            $this->__galaxy_name = $temp['Galaxy']['name'];
        }
        $matrixData = $this->__GalaxyModel->getMatrix($this->__galaxy_id);
        if (empty($this->__tabs)) {
            $this->__tabs = $matrixData['tabs'];
            $this->__matrixTags = $matrixData['matrixTags'];
            $this->__killChainOrders = $matrixData['killChain'];
            $this->__instanceUUID = $matrixData['instance-uuid'];
        }
        $this->__scope = empty($options['scope']) ? 'Event' : $options['scope'];
        $clusterData = array();
        if ($this->__scope === 'Event') {
            $clusterData = $this->__aggregate($data, $clusterData);
            if (!empty($data['Attribute'])) {
                foreach ($data['Attribute'] as $attribute) {
                    $clusterData = $this->__aggregate($attribute, $clusterData);
                }
            }
        } else {
            $clusterData = $this->__aggregate($data, $clusterData);
        }

        foreach ($clusterData as $key => $value) {
            if (empty($this->__clusterCounts[$key])) {
                $this->__clusterCounts[$key] = 1;
            } else {
                $this->__clusterCounts[$key] += 1;
            }
        }
        return '';
    }

    private function __aggregate($data, $clusterData)
    {
        if (!empty($data['Galaxy'])) {
            foreach ($data['Galaxy'] as $galaxy) {
                if ($galaxy['type'] == $this->__attackGalaxy) {
                    foreach ($galaxy['GalaxyCluster'] as $galaxyCluster) {
                        $clusterData[$galaxyCluster['tag_name']] = 1;
                    }
                }
            }
        }
        return $clusterData;
    }

    public function header($options = array())
    {
        return '';
    }

    public function footer()
    {
        if (empty($this->__GalaxyModel)) {
            return '';
        }
        $maxScore = 0;
        foreach ($this->__clusterCounts as $clusterCount) {
            if ($clusterCount > $maxScore) {
                $maxScore = $clusterCount;
            }
        }
        App::uses('ColourGradientTool', 'Tools');
        $gradientTool = new ColourGradientTool();
        $colours = $gradientTool->createGradientFromValues($this->__clusterCounts);
        $result = array(
            'target_type' => strtolower($this->__scope),
            'columnOrders' => $this->__killChainOrders,
            'tabs' => $this->__tabs,
            'scores' => $this->__clusterCounts,
            'maxScore' => $maxScore,
            'pickingMode' => false
        );
        if (!empty($colours)) {
            $result['colours'] = $colours['mapping'];
            $result['interpolation'] = $colours['interpolation'];
        }
        $result['galaxyName'] = $this->__galaxy_name;
        $result['galaxyId'] = $this->__galaxy_id;
        $matrixGalaxies = $this->__GalaxyModel->getAllowedMatrixGalaxies();
        $result['matrixGalaxies'] = $matrixGalaxies;
        return json_encode($result);
    }

    public function separator()
    {
        return '';
    }
}
