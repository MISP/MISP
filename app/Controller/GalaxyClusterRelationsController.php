<?php
App::uses('AppController', 'Controller');

class GalaxyClusterRelationsController extends AppController
{
    public $components = array('Session', 'RequestHandler');

    public $paginate = array(
            'limit' => 60,
            'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
            'recursive' => -1,
            'order' => array(
                // 'GalaxyCluster.value' => 'ASC'
            ),
            'contain' => array(
            )
    );

    public function index()
    {
        $filters = $this->IndexFilter->harvestParameters(array('context', 'searchall'));
        $aclConditions = $this->GalaxyClusterRelation->buildConditions($this->Auth->user());
        $contextConditions = array();
        if (empty($filters['context'])) {
            $filters['context'] = 'all';
        } else {
            $contextConditions = array();
            if ($filters['context'] == 'default') {
                $contextConditions = array(
                    'GalaxyClusterRelation.default' => true
                );
            } elseif ($filters['context'] == 'custom') {
                $contextConditions = array(
                    'GalaxyClusterRelation.default' => false
                );
            } elseif ($filters['context'] == 'org') {
                $contextConditions = array(
                    'GalaxyClusterRelation.org_id' => $this->Auth->user('org_id')
                );
            }
        }
        $this->set('passedArgsArray', array('context' => $filters['context'], 'searchall' => isset($filters['searchall']) ? $filters['searchall'] : ''));
        $this->set('context', $filters['context']);
        $searchConditions = array();
        if (empty($filters['searchall'])) {
            $filters['searchall'] = '';
        }
        if (strlen($filters['searchall']) > 0) {
            $searchall = '%' . strtolower($filters['searchall']) . '%';
            $searchConditions = array(
                'OR' => array(
                    'LOWER(GalaxyClusterRelation.referenced_galaxy_cluster_type) LIKE' => $searchall,
                    'LOWER(GalaxyCluster.value) LIKE' => $searchall,
                    'LOWER(ReferencedGalaxyCluster.value) LIKE' => $searchall,
                ),
            );
        }

        if ($this->_isRest()) {
            $relations = $this->GalaxyClusterRelation->find('all', 
                array(
                    'recursive' => -1,
                    'conditions' => array(
                        'AND' => array($contextConditions, $searchConditions, $aclConditions)
                    ),
                    'contain' => array('Org', 'Orgc', 'SharingGroup', 'GalaxyCluster', 'ReferencedGalaxyCluster', 'GalaxyClusterRelationTag' => array('Tag'))
                )
            );
            return $this->RestResponse->viewData($relations, $this->response->type());
        } else {
            $this->paginate['conditions']['AND'][] = $contextConditions;
            $this->paginate['conditions']['AND'][] = $searchConditions;
            $this->paginate['conditions']['AND'][] = $aclConditions;
            $this->paginate['contain'] = array_merge($this->paginate['contain'], array('Org', 'Orgc', 'SharingGroup', 'GalaxyCluster', 'ReferencedGalaxyCluster', 'GalaxyClusterRelationTag' => array('Tag')));
            $relations = $this->paginate();
            $this->loadModel('SharingGroup');
            $sgs = $this->SharingGroup->fetchAllAuthorised($this->Auth->user());
            $this->loadModel('Attribute');
            $distributionLevels = $this->Attribute->distributionLevels;
            unset($distributionLevels[5]);
            $this->set('distributionLevels', $distributionLevels);
            $this->set('data', $relations);
        }
    }

    public function add()
    {

    }

    public function edit($id)
    {

    }

    public function delete($id)
    {

    }
}