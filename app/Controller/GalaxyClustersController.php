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
				'GalaxyElement' => array(
					'conditions' => array('GalaxyElement.key' => 'synonyms'),
					'fields' => array('value')
				)
			)
	);

	public function index($id) {
		$this->paginate['conditions'] = array('GalaxyCluster.galaxy_id' => $id);
		$clusters = $this->paginate();
		if (!empty($clusters)) {
			$galaxyType = $clusters[0]['GalaxyCluster']['type'];
			$tagPattern = 'misp-galaxy:' . $galaxyType . '="%s"';
			$tags = $this->GalaxyCluster->getTags($galaxyType, false, $this->Auth->user());
			foreach ($clusters as $k => $v) {
				$clusters[$k]['GalaxyCluster']['synonyms'] = array();
				foreach ($v['GalaxyElement'] as $element) {
					$clusters[$k]['GalaxyCluster']['synonyms'][] = $element['value'];
				}
				if (isset($tags[sprintf($tagPattern, $v['GalaxyCluster']['value'])])) {
					$clusters[$k]['GalaxyCluster']['tags'] = $tags[sprintf($tagPattern, $v['GalaxyCluster']['value'])];
				} else {
					$clusters[$k]['GalaxyCluster']['tags'] = 0;
				}
			}
		}
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
		$this->set('cluster', $cluster);
	}
	
	public function attachToEvent($event_id, $tag_name) {
		$this->loadModel('Event');
		$this->Event->id = $event_id;
		$this->Event->recursive = -1;
		$event = $this->Event->read(array('id', 'org_id', 'orgc_id', 'distribution', 'sharing_group_id'), $id);
		if (empty($event)) {
			throw new MethodNotAllowedException('Invalid Event.');
		}
		if (!$this->_isSiteAdmin() && !$this->userRole['perm_sync']) {
			if (!$this->userRole['perm_tagger'] || ($this->Auth->user('org_id') !== $event['Event']['org_id'] && $this->Auth->user('org_id') !== $event['Event']['orgc_id'])) {
				throw new MethodNotAllowedException('Invalid Event.');
			}
		}
		$tag = $this->EventTag->Tag->find('first', array('conditions' => array('Tag.name' => $tag_name), 'recursive' => -1));
		if (empty($tag)) {
			$this->EventTag->Tag->create();
			$this->EventTag->Tag->save(array('name' => $tag_name, 'colour' => '#0088cc', 'exportable' => 1));
			$tag_id = $this->EventTag->Tag->id;
		} else {
			$tag_id = $tag['Tag']['id'];
		}
		$existingEventTag = $this->EventTag->find('first', array('conditions' => array('EventTag.tag_id' => $tag_id, 'EventTag.event_id' => $event_id), 'recursive' => -1));
		if (empty($existingEventTag)) {
			$this->EventTag->create();
			$this->EventTag->save(array('EventTag.tag_id' => $tag_id, 'EventTag.event_id' => $event_id));
			$this->Session->setFlash('Galaxy attached.');
		} else {
			$this->Session->setFlash('Galaxy already attached.');
		}
		$this->redirect($this->referer());
	}
	
	public function detachFromEvent($event_id, $tag_name) {
		$this->loadModel('Event');
		$this->Event->id = $event_id;
		$this->Event->recursive = -1;
		$event = $this->Event->read(array('id', 'org_id', 'orgc_id', 'distribution', 'sharing_group_id'), $id);
		if (empty($event)) {
			throw new MethodNotAllowedException('Invalid Event.');
		}
		if (!$this->_isSiteAdmin() && !$this->userRole['perm_sync']) {
			if (!$this->userRole['perm_tagger'] || ($this->Auth->user('org_id') !== $event['Event']['org_id'] && $this->Auth->user('org_id') !== $event['Event']['orgc_id'])) {
				throw new MethodNotAllowedException('Invalid Event.');
			}
		}
		$tag = $this->EventTag->Tag->find('first', array('conditions' => array('Tag.name' => $tag_name), 'recursive' => -1));
		if (empty($tag)) {
			$this->Session->setFlash('Galaxy not attached.');
		} else {
			$existingEventTag = $this->EventTag->find('first', array('conditions' => array('EventTag.tag_id' => $tag['Tag']['id'], 'EventTag.event_id' => $event_id), 'recursive' => -1));
			if (empty($existingEventTag)) {
				$this->Session->setFlash('Galaxy not attached.');
			} else {
				$this->EventTag->delete($eexistingEventTag['EventTag']['id']);
				$this->Session->setFlash('Galaxy successfully detached.');
			}
		}
		$this->redirect($this->referer());
	}
}
