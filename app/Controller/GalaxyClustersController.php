<?php
App::uses('AppController', 'Controller');

class GalaxyClustersController extends AppController {
	public $components = array('Session', 'RequestHandler');

	public $paginate = array(
			'limit' => 60,
			'maxLimit' => 9999,	// LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
			'recursive' => -1,
			'order' => array(
				'GalaxyCluster.value' => 'ASC'
			),
			'contain' => array(
				'Tag' => array(
					'fields' => array('Tag.id'),
					/*
					'EventTag' => array(
						'fields' => array('EventTag.event_id')
					),
					'AttributeTag' => array(
						'fields' => array('AttributeTag.event_id', 'AttributeTag.attribute_id')
					)
					*/
				),
				'GalaxyElement' => array(
					'conditions' => array('GalaxyElement.key' => 'synonyms'),
					'fields' => array('value')
				),
			)
	);

	public function index($id) {
		$this->paginate['conditions'] = array('GalaxyCluster.galaxy_id' => $id);
		$clusters = $this->paginate();
		$sgs = $this->GalaxyCluster->Tag->EventTag->Event->SharingGroup->fetchAllAuthorised($this->Auth->user());
		foreach ($clusters as $k => $cluster) {
			if (!empty($cluster['Tag']['id'])) {
				$clusters[$k]['GalaxyCluster']['event_count'] = $this->GalaxyCluster->Tag->EventTag->countForTag($cluster['Tag']['id'], $this->Auth->user(), $sgs);
			}
		}
		$tagIds = array();
		$sightings = array();
		if (!empty($clusters)) {
			$galaxyType = $clusters[0]['GalaxyCluster']['type'];
			foreach ($clusters as $k => $v) {
				$clusters[$k]['event_ids'] = array();
				if (!empty($v['Tag'])) {
					$tagIds[] = $v['Tag']['id'];
					$clusters[$k]['GalaxyCluster']['tag_id'] = $v['Tag']['id'];
				}
				$clusters[$k]['GalaxyCluster']['synonyms'] = array();
				foreach ($v['GalaxyElement'] as $element) {
					$clusters[$k]['GalaxyCluster']['synonyms'][] = $element['value'];
				}
			}
		}
		$this->loadModel('Sighting');
		$sightings['tags'] = array();
		foreach ($clusters as $k => $cluster) {
			if (!empty($cluster['GalaxyCluster']['tag_id'])) {
				$temp = $this->Sighting->getSightingsForTag($this->Auth->user(), $cluster['GalaxyCluster']['tag_id']);
				$clusters[$k]['sightings'] = $temp;
			}
		}
		foreach ($clusters as $k => $cluster) {
			$startDate = !empty($cluster['sightings']) ? min(array_keys($cluster['sightings'])) : date('Y-m-d');
			$startDate = date('Y-m-d', strtotime("-3 days", strtotime($startDate)));
			$to = date('Y-m-d', time());
			for ($date = $startDate; strtotime($date) <= strtotime($to); $date = date('Y-m-d',strtotime("+1 day", strtotime($date)))) {
				if (!isset($csv[$k])) {
					$csv[$k] = 'Date,Close\n';
				}
				if (isset($cluster['sightings'][$date])) {
					$csv[$k] .= $date . ',' . $cluster['sightings'][$date] . '\n';
				} else {
					$csv[$k] .= $date . ',0\n';
				}
			}
		}
		$this->set('csv', $csv);
		$this->set('list', $clusters);
		if ($this->request->is('ajax')) {
			$this->layout = 'ajax';
			$this->render('ajax/index');
		}
	}

	public function view($id) {
		$cluster = $this->GalaxyCluster->find('first', array(
			'recursive' => -1,
			'contain' => array('Galaxy'),
			'conditions' => array('GalaxyCluster.id' => $id)
		));
		if (!empty($cluster)) {
			$galaxyType = $cluster['GalaxyCluster']['type'];
			$this->loadModel('Tag');
			$tag = $this->Tag->find('first', array(
					'conditions' => array(
							'name' => $cluster['GalaxyCluster']['tag_name']
					),
					'fields' => array('id'),
					'recursive' => -1,
					'contain' => array('EventTag.tag_id')
			));
			if (!empty($tag)) {
				$cluster['GalaxyCluster']['tag_count'] = count($tag['EventTag']);
				$cluster['GalaxyCluster']['tag_id'] = $tag['Tag']['id'];
			}
		}
		$this->set('id', $id);
		$this->set('galaxy_id' , $cluster['Galaxy']['id']);
		$this->set('cluster', $cluster);
	}

	public function attachToEvent($event_id, $tag_name) {
		$this->loadModel('Event');
		$this->Event->id = $event_id;
		$this->Event->recursive = -1;
		$event = $this->Event->read(array(), $event_id);
		if (empty($event)) {
			throw new MethodNotAllowedException('Invalid Event.');
		}
		if (!$this->_isSiteAdmin() && !$this->userRole['perm_sync']) {
			if (!$this->userRole['perm_tagger'] || ($this->Auth->user('org_id') !== $event['Event']['org_id'] && $this->Auth->user('org_id') !== $event['Event']['orgc_id'])) {
				throw new MethodNotAllowedException('Invalid Event.');
			}
		}
		$tag = $this->Event->EventTag->Tag->find('first', array('conditions' => array('Tag.name' => $tag_name), 'recursive' => -1));
		if (empty($tag)) {
			$this->Event->EventTag->Tag->create();
			$this->Event->EventTag->Tag->save(array('name' => $tag_name, 'colour' => '#0088cc', 'exportable' => 1));
			$tag_id = $this->Event->EventTag->Tag->id;
		} else {
			$tag_id = $tag['Tag']['id'];
		}
		$existingEventTag = $this->Event->EventTag->find('first', array('conditions' => array('EventTag.tag_id' => $tag_id, 'EventTag.event_id' => $event_id), 'recursive' => -1));
		if (empty($existingEventTag)) {
			$cluster = $this->GalaxyCluster->find('first', array(
				'recursive' => -1,
				'conditions' => array('GalaxyCluster.tag_name' => $existingEventTag['Tag']['name'])
			));
			$this->Event->EventTag->create();
			$this->Event->EventTag->save(array('EventTag.tag_id' => $tag_id, 'EventTag.event_id' => $event_id));
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
			$event['Event']['published'] = 0;
			$date = new DateTime();
			$event['Event']['timestamp'] = $date->getTimestamp();
			$this->Event->save($event);
			$this->Session->setFlash('Galaxy attached.');
		} else {
			$this->Session->setFlash('Galaxy already attached.');
		}
		$this->redirect($this->referer());
	}

	public function detachFromEvent($event_id, $tag_id) {
		$this->loadModel('Event');
		$this->Event->id = $event_id;
		$this->Event->recursive = -1;
		$event = $this->Event->read(array(), $event_id);
		if (empty($event)) {
			throw new MethodNotAllowedException('Invalid Event.');
		}
		if (!$this->_isSiteAdmin() && !$this->userRole['perm_sync']) {
			if (!$this->userRole['perm_tagger'] || ($this->Auth->user('org_id') !== $event['Event']['org_id'] && $this->Auth->user('org_id') !== $event['Event']['orgc_id'])) {
				throw new MethodNotAllowedException('Invalid Event.');
			}
		}
		$existingEventTag = $this->Event->EventTag->find('first', array(
			'conditions' => array('EventTag.tag_id' => $tag_id, 'EventTag.event_id' => $event_id),
			'recursive' => -1,
			'contain' => array('Tag')
		));
		if (empty($existingEventTag)) {
			$this->Session->setFlash('Galaxy not attached.');
		} else {
			$cluster = $this->GalaxyCluster->find('first', array(
				'recursive' => -1,
				'conditions' => array('GalaxyCluster.tag_name' => $existingEventTag['Tag']['name'])
			));
			$result = $this->Event->EventTag->delete($existingEventTag['EventTag']['id']);
			if ($result) {
				$event['Event']['published'] = 0;
				$date = new DateTime();
				$event['Event']['timestamp'] = $date->getTimestamp();
				$this->Event->save($event);
				$this->Session->setFlash('Galaxy successfully detached.');
				$this->Log = ClassRegistry::init('Log');
				$this->Log->create();
				$this->Log->save(array(
					'org' => $this->Auth->user('Organisation')['name'],
					'model' => 'Event',
					'model_id' => $event_id,
					'email' => $this->Auth->user('email'),
					'action' => 'galaxy',
					'title' => 'Detached ' . $cluster['GalaxyCluster']['value'] . ' (' . $cluster['GalaxyCluster']['id'] . ') from event (' . $event_id . ')',
					'change' => ''
				));
			} else {
				$this->Session->setFlash('Could not detach galaxy from event.');
			}
		}
		$this->redirect($this->referer());
	}
}
