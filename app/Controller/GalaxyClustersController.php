<?php
App::uses('AppController', 'Controller');

class GalaxyClustersController extends AppController
{
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

    public function index($id)
    {
        $this->paginate['conditions'] = array('GalaxyCluster.galaxy_id' => $id);
        if (isset($this->params['named']['searchall']) && strlen($this->params['named']['searchall']) > 0) {
            $synonym_hits = $this->GalaxyCluster->GalaxyElement->find(
                'list',
                array(
                    'recursive' => -1,
                    'conditions' => array(
                        'LOWER(GalaxyElement.value) LIKE' => '%' . strtolower($this->params['named']['searchall']) . '%',
                        'GalaxyElement.key' => 'synonyms' ),
                        'fields' => array(
                            'GalaxyElement.galaxy_cluster_id')
                        )
            );
            $this->paginate['conditions'] =
                array("AND" => array(
                    'OR' => array(
                        "LOWER(GalaxyCluster.value) LIKE" => '%'. strtolower($this->params['named']['searchall']) .'%',
                        "LOWER(GalaxyCluster.description) LIKE" => '%'. strtolower($this->params['named']['searchall']) .'%',
                        "GalaxyCluster.id" => array_values($synonym_hits)
                    ),
                    "GalaxyCluster.galaxy_id" => $id
                    ));
            $this->set('passedArgsArray', array('all'=>$this->params['named']['searchall']));
        }
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
        $csv = array();
        foreach ($clusters as $k => $cluster) {
            $startDate = !empty($cluster['sightings']) ? min(array_keys($cluster['sightings'])) : date('Y-m-d');
            $startDate = date('Y-m-d', strtotime("-3 days", strtotime($startDate)));
            $to = date('Y-m-d', time());
            for ($date = $startDate; strtotime($date) <= strtotime($to); $date = date('Y-m-d', strtotime("+1 day", strtotime($date)))) {
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
        $this->set('galaxy_id', $id);
        if ($this->request->is('ajax')) {
            $this->layout = 'ajax';
            $this->render('ajax/index');
        }
    }

    public function view($id)
    {
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
        $this->set('galaxy_id', $cluster['Galaxy']['id']);
        $this->set('cluster', $cluster);
    }

    public function attachToEvent($event_id, $tag_name)
    {
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
            $this->Flash->success('Galaxy attached.');
        } else {
            $this->Flash->error('Galaxy already attached.');
        }
        $this->redirect($this->referer());
    }

    public function detach($target_id, $target_type, $tag_id)
    {
        $this->loadModel('Event');
        if ($target_type == 'attribute') {
            $attribute = $this->Event->Attribute->find('first', array(
                'recursive' => -1,
                'fields' => array('id', 'event_id'),
                'conditions' => array('Attribute.id' => $target_id)
            ));
            if (empty($attribute)) {
                throw new MethodNotAllowedException('Invalid Attribute.');
            }
            $event_id = $attribute['Attribute']['event_id'];
        } elseif ($target_type == 'event') {
            $event_id = $target_id;
        } else {
            throw new MethodNotAllowedException('Invalid options');
        }
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
        if ($target_type == 'attribute') {
            $existingTargetTag = $this->Event->Attribute->AttributeTag->find('first', array(
                'conditions' => array('AttributeTag.tag_id' => $tag_id, 'AttributeTag.attribute_id' => $target_id),
                'recursive' => -1,
                'contain' => array('Tag')
            ));
        } elseif ($target_type == 'event') {
            $existingTargetTag = $this->Event->EventTag->find('first', array(
                'conditions' => array('EventTag.tag_id' => $tag_id, 'EventTag.event_id' => $target_id),
                'recursive' => -1,
                'contain' => array('Tag')
            ));
        }

        if (empty($existingTargetTag)) {
            $this->Flash->error('Galaxy not attached.');
        } else {
            $cluster = $this->GalaxyCluster->find('first', array(
                'recursive' => -1,
                'conditions' => array('GalaxyCluster.tag_name' => $existingTargetTag['Tag']['name'])
            ));
            if ($target_type == 'event') {
                $result = $this->Event->EventTag->delete($existingTargetTag['EventTag']['id']);
            } elseif ($target_type == 'attribute') {
                $result = $this->Event->Attribute->AttributeTag->delete($existingTargetTag['AttributeTag']['id']);
            }
            if ($result) {
                $event['Event']['published'] = 0;
                $date = new DateTime();
                $event['Event']['timestamp'] = $date->getTimestamp();
                $this->Event->save($event);
                $this->Flash->success('Galaxy successfully detached.');
                $this->Log = ClassRegistry::init('Log');
                $this->Log->create();
                $this->Log->save(array(
                    'org' => $this->Auth->user('Organisation')['name'],
                    'model' => ucfirst($target_type),
                    'model_id' => $target_id,
                    'email' => $this->Auth->user('email'),
                    'action' => 'galaxy',
                    'title' => 'Detached ' . $cluster['GalaxyCluster']['value'] . ' (' . $cluster['GalaxyCluster']['id'] . ') from ' . $target_type . ' (' . $target_id . ')',
                    'change' => ''
                ));
            } else {
                $this->Flash->error('Could not detach galaxy from event.');
            }
        }
        $this->redirect($this->referer());
    }

	public function delete($id) {
		{
			if ($this->request->is('post')) {
				$result = false;
				$galaxy_cluster = $this->GalaxyCluster->find('first', array(
					'recursive' => -1,
					'conditions' => array('GalaxyCluster.id' => $id)
				));
				if (!empty($galaxy_cluster)) {
					$result = $this->GalaxyCluster->delete($id, true);
					$galaxy_id = $galaxy_cluster['GalaxyCluster']['galaxy_id'];
				}
				if ($result) {
					$message = 'Galaxy cluster successfuly deleted.';
					if ($this->_isRest()) {
						return $this->RestResponse->saveSuccessResponse('GalaxyCluster', 'delete', $id, $this->response->type());
					} else {
						$this->Flash->success($message);
						$this->redirect(array('controller' => 'galaxies', 'action' => 'view', $galaxy_id));
					}
				} else {
					$message = 'Galaxy cluster could not be deleted.';
					if ($this->_isRest()) {
						return $this->RestResponse->saveFailResponse('GalaxyCluster', 'delete', $id, $message, $this->response->type());
					} else {
						$this->Flash->error($message);
						$this->redirect(array('controller' => 'taxonomies', 'action' => 'index'));
					}
				}
			} else {
				if ($this->request->is('ajax')) {
					$this->set('id', $id);
					$this->render('ajax/galaxy_cluster_delete_confirmation');
				} else {
					throw new MethodNotAllowedException('This function can only be reached via AJAX.');
				}
			}
		}
	}
}
