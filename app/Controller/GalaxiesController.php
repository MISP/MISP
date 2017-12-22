	<?php
App::uses('AppController', 'Controller');

class GalaxiesController extends AppController {
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

	public function index() {
		if ($this->_isRest()) {
			$galaxies = $this->Galaxy->find('all',array('recursive' => -1));
			return $this->RestResponse->viewData($galaxies, $this->response->type());
		}else{
			$galaxies = $this->paginate();
			$this->set('list', $galaxies);
		}
	}

	public function update() {
		if (!$this->request->is('post')) throw new MethodNotAllowedException('This action is only accessible via POST requests.');
		$result = $this->Galaxy->update();
		$message = 'Galaxies updated.';
		if ($this->_isRest()) {
			return $this->RestResponse->saveSuccessResponse('Galaxy', 'update', false, $this->response->type(), $message);
		} else {
			$this->Session->setFlash($message);
			$this->redirect(array('controller' => 'galaxies', 'action' => 'index'));
		}
	}

	public function view($id) {
		if (!is_numeric($id)) throw new NotFoundException('Invalid galaxy.');
		if ($this->_isRest()) {
			$galaxy = $this->Galaxy->find('first', array(
					'contain' => array('GalaxyCluster' => array('GalaxyElement'/*, 'GalaxyReference'*/)),
					'recursive' => -1,
					'conditions' => array('Galaxy.id' => $id)
			));
			if (empty($galaxy)) {
				throw new NotFoundException('Galaxy not found.');
			}
			$this->set('Galaxy', $galaxy);
			$this->set('_serialize', array('Galaxy'));
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

	public function selectGalaxy($event_id) {
		$galaxies = $this->Galaxy->find('all', array('recursive' => -1));
		$this->set('galaxies', $galaxies);
		$this->set('event_id', $event_id);
		$this->render('ajax/galaxy_choice');
	}

	public function selectCluster($event_id, $selectGalaxy = false) {
		$conditions = array();
		if ($selectGalaxy) {
			$conditions = array('GalaxyCluster.galaxy_id' => $selectGalaxy);
		}
		$data = $this->Galaxy->GalaxyCluster->find('all', array(
				'conditions' => $conditions,
				'fields' => array('value', 'description', 'source'),
				'contain' => array('GalaxyElement' => array('conditions' => array('GalaxyElement.key' => 'synonyms'))),
				'recursive' => -1
		));
		$clusters = array();
		$lookup_table = array();
		foreach ($data as $k => $cluster) {
			$cluster['GalaxyCluster']['synonyms_string'] = array();
			foreach ($cluster['GalaxyElement'] as $element) {
				$cluster['GalaxyCluster']['synonyms_string'][] = $element['value'];
				if (isset($lookup_table[$element['value']])) {
					$lookup_table[$element['value']][] = $cluster['GalaxyCluster']['id'];
				} else {
					$lookup_table[$element['value']] = array($cluster['GalaxyCluster']['id']);
				}
			}
			$cluster['GalaxyCluster']['synonyms_string'] = implode(', ', $cluster['GalaxyCluster']['synonyms_string']);
			unset($cluster['GalaxyElement']);
			$clusters[$cluster['GalaxyCluster']['value']] = $cluster['GalaxyCluster'];
			if (isset($lookup_table[$cluster['GalaxyCluster']['value']])) {
				$lookup_table[$cluster['GalaxyCluster']['value']][] = $cluster['GalaxyCluster']['id'];
			} else {
				$lookup_table[$cluster['GalaxyCluster']['value']] = array($cluster['GalaxyCluster']['id']);
			}
		}
		ksort($clusters);
		$this->set('clusters', $clusters);
		$this->set('event_id', $event_id);
		$this->set('lookup_table', $lookup_table);
		$this->render('ajax/cluster_choice');
	}

	public function attachClusterToEvent($event_id) {
		$cluster_id = $this->request->data['Galaxy']['target_id'];
		$cluster = $this->Galaxy->GalaxyCluster->find('first', array('recursive' => -1, 'conditions' => array('id' => $cluster_id), 'fields' => array('tag_name', 'id', 'value')));
		$this->loadModel('Tag');
		$event = $this->Tag->EventTag->Event->fetchEvent($this->Auth->user(), array('eventid' => $event_id, 'metadata' => 1));
		if (empty($event)) {
			throw new NotFoundException('Invalid event.');
		}
		$event = $event[0];
		$tag_id = $this->Tag->captureTag(array('name' => $cluster['GalaxyCluster']['tag_name'], 'colour' => '#0088cc', 'exportable' => 1), $this->Auth->user());
		if ($tag_id === false) {
			throw new MethodNotAllowedException('Could not attach cluster.');
		}
		$this->Tag->EventTag->create();
		$existingTag = $this->Tag->EventTag->find('first', array('conditions' => array('event_id' => $event_id, 'tag_id' => $tag_id)));
		if (!empty($existingTag)) {
			$this->Session->setFlash('Cluster already attached.');
			$this->redirect($this->referer());
		}
		$result = $this->Tag->EventTag->save(array('event_id' => $event_id, 'tag_id' => $tag_id));
		if ($result) {
			$event['Event']['published'] = 0;
			$date = new DateTime();
			$event['Event']['timestamp'] = $date->getTimestamp();
			$this->Tag->EventTag->Event->save($event);
			$this->Log = ClassRegistry::init('Log');
			$this->Log->create();
			$this->Log->save(array(
				'org' => $this->Auth->user('Organisation')['name'],
				'model' => 'Event',
				'model_id' => $event_id,
				'email' => $this->Auth->user('email'),
				'action' => 'galaxy',
				'title' => 'Attached ' . $cluster['GalaxyCluster']['value'] . ' (' . $cluster['GalaxyCluster']['id'] . ') to event (' . $event_id . ')',
				'change' => ''
			));
			$this->Session->setFlash('Cluster attached');
			$this->redirect($this->referer());
		} else {
			$this->Session->setFlash('Cluster could not be attached');
			$this->redirect($this->referer());
		}
	}

	public function viewGraph($id) {
		$cluster = $this->Galaxy->GalaxyCluster->find('first', array(
			'conditions' => array('GalaxyCluster.id' => $id),
			'contain' => array('Galaxy'),
			'recursive' => -1
		));
		if (empty($cluster)) throw new MethodNotAllowedException('Invalid Galaxy.');
		$this->set('cluster', $cluster);
		$this->set('scope', 'galaxy');
		$this->set('id', $id);
		$this->set('galaxy_id' , $cluster['Galaxy']['id']);
		$this->render('/Events/view_graph');
	}
}
