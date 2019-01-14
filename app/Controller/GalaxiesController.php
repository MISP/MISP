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
        } else {
            $force = 0;
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

        $items = array();
        $items[__('All clusters')] = "/galaxies/selectCluster/" . h($target_id) . '/' . h($target_type) . '/0';
        foreach ($galaxies as $galaxy) {
            if ($galaxy['Galaxy']['id'] != -1) {
                // construct option template
                $galaxyTemplate = '<it class="fa fa-{{=it.icon}}" style="width: 22px;"></it>';
                $galaxyTemplate .= '{{=it.name}}';
                if (strlen($galaxy['Galaxy']['description']) < 50) {
                    $galaxyTemplate .= '<i style="float:right; font-size: smaller;">{{=it.description}}</i>';
                } else {
                    $galaxyTemplate .= '<it class="fa fa-info-circle" style="float:right;" title="{{=it.description}}"></it>';
                }

                $items[$galaxy['Galaxy']['name']] = array(
                    'value' => "/galaxies/selectCluster/" . h($target_id) . '/' . h($target_type) . '/' . h($galaxy['Galaxy']['id']),
                    'template' => $galaxyTemplate,
                    'templateData' => array(
                        'icon' => h($galaxy['Galaxy']['icon']),
                        'name' => h($galaxy['Galaxy']['name']),
                        'description' => h($galaxy['Galaxy']['description'])
                    )
                );
            } else { // attackMatrix
                $items[$galaxy['Galaxy']['name']] = array(
                    'functionName' => "getMitreMatrixPopup('" . h($target_id) . "/" . h($target_type) . "')",
                    'isPill' => true,
                    'img' => "/img/mitre-attack-icon.ico",
                );
            }
        }

        $this->set('items', $items);
        $this->render('/Elements/generic_picker');
    }

    public function selectGalaxyNamespace($target_id, $target_type='event')
    {
        $namespaces = $this->Galaxy->find('list', array(
            'recursive' => -1,
            'fields' => array('namespace', 'namespace'),
            'group' => array('namespace')
        ));

        $items = array();
        $items[__('All namespaces')] = "/galaxies/selectGalaxy/" . h($target_id) . '/' . h($target_type) . '/0';
        foreach ($namespaces as $namespace) {
            $items[h($namespace)] = "/galaxies/selectGalaxy/" . h($target_id) . '/' . h($target_type) . '/' . h($namespace);
        }

        $this->set('items', $items);
        $this->set('options', array( // set chosen (select picker) options
            'multiple' => 0,
        ));
        $this->render('/Elements/generic_picker');
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
        $this->set('target_id', $target_id);
        $this->set('target_type', $target_type);

        $items = array();
        foreach ($clusters as $namespace => $cluster_data) {
            foreach ($cluster_data as $k => $cluster) {
                $clusterTemplate = '{{=it.name}}';
                if (strlen($cluster['description']) < 50) {
                    $clusterTemplate .= '<i style="float:right; font-size: smaller;">{{=it.description}}</i>';
                } else {
                    $clusterTemplate .= '<it class="fa fa-info-circle" style="float:right;" title="{{=it.description}}"></it>';
                }
                if ($cluster['synonyms_string'] !== "") {
                    $clusterTemplate .= '<div class="apply_css_arrow" style="padding-left: 5px; font-size: smaller;"><i>{{=it.synonyms_string}}</i></div>';
                }

                $target_type = h($target_type);
                $target_id = h($target_id);
                $cluster_id = h($cluster['id']);
                $title = __('Synonyms: ') . h($cluster['synonyms_string']);
                $name = h($cluster['value']);
                $optionName = h($cluster['value']) . ' (' . h($cluster['synonyms_string']) . ')';
                $items[$optionName] = array(
                    'value' => h($cluster_id),
                    'title' => $title,
                    'additionalData' => array(
                        'target_id' => $target_id,
                        'target_type' => $target_type,
                    ),
                    'template' => $clusterTemplate,
                    'templateData' => array(
                        'name' => $name,
                        'description' => h($cluster['description']),
                        'synonyms_string' => $title
                    )
                );
            }
        }
        $onClickForm = 'quickSubmitGalaxyForm';

        $this->set('items', $items);
        $this->set('options', array( // set chosen (select picker) options
            'functionName' => $onClickForm,
            'multiple' => '-1',
        ));
        $this->render('ajax/cluster_choice');
    }

    public function attachCluster($target_id, $target_type = 'event')
    {
        $cluster_id = $this->request->data['Galaxy']['target_id'];
        $result = $this->Galaxy->attachCluster($this->Auth->user(), $target_type, $target_id, $cluster_id);
        return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => $result, 'check_publish' => true)), 'status'=>200, 'type' => 'json'));
    }

    public function attachMultipleClusters($target_id, $target_type = 'event')
    {
        if (!empty($this->request->data['Galaxy']['target_ids'])) {
            $cluster_ids = json_decode($this->request->data['Galaxy']['target_ids'], true);
            if ($cluster_ids === null) {
                return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'error' => __('Failed to parse request.'))), 'status'=>200, 'type' => 'json'));
            }
        } else {
            return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'error' => __('No clusters picked.'))), 'status'=>200, 'type' => 'json'));
        }
        $result = "";
        if (!is_array($cluster_ids)) { // in case we only want to attach 1
            $cluster_ids = array($cluster_ids);
        }
        foreach ($cluster_ids as $cluster_id) {
            $result = $this->Galaxy->attachCluster($this->Auth->user(), $target_type, $target_id, $cluster_id);
        }
        if ($this->request->is('ajax')) {
            return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => $result, 'check_publish' => true)), 'status'=>200, 'type' => 'json'));
        } else {
            $this->Flash->info($result);
            $this->redirect($this->referer());
        }
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

    public function showGalaxies($id, $scope = 'event')
    {
        $this->layout = 'ajax';
        $this->set('scope', $scope);
        if ($scope == 'event') {
            $this->loadModel('Event');
            $object = $this->Event->fetchEvent($this->Auth->user(), array('eventid' => $id, 'metadata' => 1));
            if (empty($object)) {
                throw new MethodNotAllowedException('Invalid event.');
            }
            $this->set('object', $object[0]);

        } elseif ($scope == 'attribute') {
            $this->loadModel('Attribute');
            $object = $this->Attribute->fetchAttributes($this->Auth->user(), array('conditions' => array('Attribute.id' => $id)));
            if (empty($object)) {
                throw new MethodNotAllowedException('Invalid attribute.');
            }
            $object[0] = $this->Attribute->Event->massageTags($object[0], 'Attribute');
        }
        $this->set('object', $object[0]);
        $this->render('/Events/ajax/ajaxGalaxies');
    }
}
