<?php
App::uses('AppController', 'Controller');

class GalaxiesController extends AppController
{
    public $components = array('Session', 'RequestHandler');

    public $paginate = array(
            'limit' => 60,
            'maxLimit' => 9999,	// LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
            'contain' => array(

            ),
            'order' => array(
                'Galaxy.id' => 'DESC'
            ),
    );

    public function index()
    {
        if ($this->_isRest()) {
            $galaxies = $this->Galaxy->find('all', array('recursive' => -1));
            return $this->RestResponse->viewData($galaxies, $this->response->type());
        } else {
            $galaxies = $this->paginate();
            $this->set('list', $galaxies);
        }
    }

    public function update()
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException('This action is only accessible via POST requests.');
        }
        if (!empty($this->params['named']['force'])) {
            $force = 1;
        }
        $result = $this->Galaxy->update($force);
        $message = 'Galaxies updated.';
        if ($this->_isRest()) {
            return $this->RestResponse->saveSuccessResponse('Galaxy', 'update', false, $this->response->type(), $message);
        } else {
            $this->Flash->success($message);
            $this->redirect(array('controller' => 'galaxies', 'action' => 'index'));
        }
    }

    public function view($id)
    {
        if (!is_numeric($id)) {
            throw new NotFoundException('Invalid galaxy.');
        }
        if (isset($this->params['named']['searchall']) && strlen($this->params['named']['searchall']) > 0) {
            $this->set('passedArgsArray', array('all' => $this->params['named']['searchall']));
        }
        if ($this->_isRest()) {
            $galaxy = $this->Galaxy->find('first', array(
                    'contain' => array('GalaxyCluster' => array('GalaxyElement'/*, 'GalaxyReference'*/)),
                    'recursive' => -1,
                    'conditions' => array('Galaxy.id' => $id)
            ));
            if (empty($galaxy)) {
                throw new NotFoundException('Galaxy not found.');
            }
            return $this->RestResponse->viewData($galaxy, $this->response->type());
        } else {
            $galaxy = $this->Galaxy->find('first', array(
                    'recursive' => -1,
                    'conditions' => array('Galaxy.id' => $id)
            ));
            if (empty($galaxy)) {
                throw new NotFoundException('Galaxy not found.');
            }
            $this->set('galaxy', $galaxy);
        }
    }

    public function selectGalaxy($target_id, $target_type='event', $namespace='misp')
    {
        $expectedDescription = 'ATT&CK Tactic';
        $conditions = $namespace == '0' ? array() : array('namespace' => $namespace);
        if ($namespace == 'mitre-attack' || $namespace == '0') {
            $conditions[] = array('description !=' => $expectedDescription);
            $conditions2 = array('namespace' => 'mitre-attack');
            $conditions2[] = array('description' => $expectedDescription);

            $tacticGalaxies = $this->Galaxy->find('all', array(
                'recursive' => -1,
                'conditions' => $conditions2,
            ));
        }
        $galaxies = $this->Galaxy->find('all', array(
            'recursive' => -1,
            'conditions' => $conditions,
        ));
        if (!empty($tacticGalaxies)) {
            array_unshift($galaxies, array('Galaxy' => array(
                'id' => '-1',
                'uuid' => '-1',
                'name' => $expectedDescription,
                'type' => '-1',
                'icon' => '/img/mitre-attack-icon.ico',
                'namespace' => 'mitre-attack'
            )));
        }
        $this->set('galaxies', $galaxies);
        $this->set('target_id', $target_id);
        $this->set('target_type', $target_type);
        $this->render('ajax/galaxy_choice');
    }

    public function selectGalaxyNamespace($target_id, $target_type='event')
    {
        $namespaces = $this->Galaxy->find('list', array(
            'recursive' => -1,
            'fields' => array('namespace', 'namespace'),
            'group' => array('namespace')
        ));
        $this->set('namespaces', $namespaces);
        $this->set('target_id', $target_id);
        $this->set('target_type', $target_type);
        $this->render('ajax/galaxy_namespace_choice');
    }

    public function selectCluster($target_id, $target_type = 'event', $selectGalaxy = false)
    {
        $conditions = array();
        if ($selectGalaxy) {
            $conditions = array('GalaxyCluster.galaxy_id' => $selectGalaxy);
        }
        $data = $this->Galaxy->GalaxyCluster->find('all', array(
                'conditions' => $conditions,
                'fields' => array('value', 'description', 'source', 'type'),
                'contain' => array(
                    'GalaxyElement' => array(
                        'conditions' => array('GalaxyElement.key' => 'synonyms')
                    )
                ),
                'recursive' => -1
        ));
        $clusters = array();
        $lookup_table = array();
        foreach ($data as $k => $cluster) {
            $cluster['GalaxyCluster']['synonyms_string'] = array();
            foreach ($cluster['GalaxyElement'] as $element) {
                $cluster['GalaxyCluster']['synonyms_string'][] = $element['value'];
                if (isset($lookup_table[$cluster['GalaxyCluster']['type']][$element['value']])) {
                    $lookup_table[$cluster['GalaxyCluster']['type']][$element['value']][] = $cluster['GalaxyCluster']['id'];
                } else {
                    $lookup_table[$cluster['GalaxyCluster']['type']][$element['value']] = array($cluster['GalaxyCluster']['id']);
                }
            }
            $cluster['GalaxyCluster']['synonyms_string'] = implode(', ', $cluster['GalaxyCluster']['synonyms_string']);
            unset($cluster['GalaxyElement']);
            $clusters[$cluster['GalaxyCluster']['type']][$cluster['GalaxyCluster']['value']] = $cluster['GalaxyCluster'];
            if (isset($lookup_table[$cluster['GalaxyCluster']['type']][$cluster['GalaxyCluster']['value']])) {
                $lookup_table[$cluster['GalaxyCluster']['type']][$cluster['GalaxyCluster']['value']][] = $cluster['GalaxyCluster']['id'];
            } else {
                $lookup_table[$cluster['GalaxyCluster']['type']][$cluster['GalaxyCluster']['value']] = array($cluster['GalaxyCluster']['id']);
            }
        }
        ksort($clusters);
        $this->set('clusters', $clusters);
        $this->set('target_id', $target_id);
        $this->set('target_type', $target_type);
        $this->set('lookup_table', $lookup_table);
        $this->render('ajax/cluster_choice');
    }

    public function attachCluster($target_id, $target_type = 'event')
    {
        $cluster_id = $this->request->data['Galaxy']['target_id'];
        $result = $this->Galaxy->attachCluster($this->Auth->user(), $target_type, $target_id, $cluster_id);
        $this->Flash->info($result);
        $this->redirect($this->referer());
    }

    public function attachMultipleClusters($target_id, $target_type = 'event')
    {
        $cluster_ids = json_decode($this->request->data['Galaxy']['target_ids'], true);
        $result = "";
        foreach ($cluster_ids as $cluster_id) {
            $result = $this->Galaxy->attachCluster($this->Auth->user(), $target_type, $target_id, $cluster_id);
        }
        $this->Flash->info($result);
        $this->redirect($this->referer());
    }

    public function viewGraph($id)
    {
        $cluster = $this->Galaxy->GalaxyCluster->find('first', array(
            'conditions' => array('GalaxyCluster.id' => $id),
            'contain' => array('Galaxy'),
            'recursive' => -1
        ));
        if (empty($cluster)) {
            throw new MethodNotAllowedException('Invalid Galaxy.');
        }
        $this->set('cluster', $cluster);
        $this->set('scope', 'galaxy');
        $this->set('id', $id);
        $this->set('galaxy_id', $cluster['Galaxy']['id']);
        $this->render('/Events/view_graph');
    }
}
