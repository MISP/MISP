<?php

App::uses('AppController', 'Controller');

/**
 * Tags Controller
 *
 * @property Tag $Tag
 */

class TagsController extends AppController {
	public $components = array('Security' ,'RequestHandler');

	public $paginate = array(
			'limit' => 50,
			'order' => array(
					'Tag.name' => 'asc'
			)
	);

	public $helpers = array('TextColour');

	public function beforeFilter() { // TODO REMOVE
		parent::beforeFilter();
	}

	public function index($favouritesOnly = false) {
		$this->loadModel('Event');
		$this->loadModel('Taxonomy');
		$taxonomies = $this->Taxonomy->listTaxonomies(array('full' => false, 'enabled' => true));
		$taxonomyNamespaces = array();
		if (!empty($taxonomies)) foreach ($taxonomies as &$taxonomy) $taxonomyNamespaces[$taxonomy['namespace']] = $taxonomy;
		$taxonomyTags = array();
		$this->Event->recursive = -1;
		$this->paginate['contain'] = array('EventTag' => array('fields' => 'event_id'), 'FavouriteTag');
		if ($favouritesOnly) {
			$tag_id_list = $this->Tag->FavouriteTag->find('list', array(
					'conditions' => array('FavouriteTag.user_id' => $this->Auth->user('id')),
					'fields' => array('FavouriteTag.tag_id')
			));
			if (empty($tag_id_list)) $tag_id_list = array(-1);
			$this->paginate['conditions']['AND']['Tag.id'] = $tag_id_list;
		}
		$paginated = $this->paginate();
		foreach ($paginated as $k => &$tag) {
			$eventIDs = array();
			if (empty($tag['EventTag'])) $tag['Tag']['count'] = 0;
			else {
				foreach ($tag['EventTag'] as $eventTag) {
					$eventIDs[] = $eventTag['event_id'];
				}
				$conditions = array('Event.id' => $eventIDs);
				if (!$this->_isSiteAdmin()) $conditions = array_merge(
					$conditions,
					array('OR' => array(
						array('AND' => array(
							array('Event.distribution >' => 0),
							array('Event.published =' => 1)
						)),
						array('Event.orgc_id' => $this->Auth->user('org_id'))
					)));
				$events = $this->Event->find('all', array(
					'fields' => array('Event.id', 'Event.distribution', 'Event.orgc_id'),
					'conditions' => $conditions
				));
				$tag['Tag']['count'] = count($events);
			}
			unset($tag['EventTag']);
			if (!empty($tag['FavouriteTag'])) {
				foreach ($tag['FavouriteTag'] as &$ft) if ($ft['user_id'] == $this->Auth->user('id')) $tag['Tag']['favourite'] = true;
				if (!isset($tag['Tag']['favourite'])) $tag['Tag']['favourite'] = false;
			} else $tag['Tag']['favourite'] = false;
			unset($tag['FavouriteTag']);
			if (!empty($taxonomyNamespaces)) {
				$taxonomyNamespaceArrayKeys = array_keys($taxonomyNamespaces);
				foreach ($taxonomyNamespaceArrayKeys as &$tns) {
					if (substr(strtoupper($tag['Tag']['name']), 0, strlen($tns)) === strtoupper($tns)) {
						$tag['Tag']['Taxonomy'] = $taxonomyNamespaces[$tns];
						if (!isset($taxonomyTags[$tns])) $taxonomyTags[$tns] = $this->Taxonomy->getTaxonomyTags($taxonomyNamespaces[$tns]['id'], true);
						$tag['Tag']['Taxonomy']['expanded'] = $taxonomyTags[$tns][strtoupper($tag['Tag']['name'])];
					}
				}
			}
		}
		if ($this->_isRest()) {
			foreach ($paginated as &$tag) {
				$tag = $tag['Tag'];
			}
			$this->set('Tag', $paginated);
			$this->set('_serialize', array('Tag'));
		} else {
			$this->set('list', $paginated);
			$this->set('favouritesOnly', $favouritesOnly);
		}
		// send perm_tagger to view for action buttons
	}

	public function add() {
		if (!$this->_isSiteAdmin() && !$this->userRole['perm_tag_editor']) throw new NotFoundException('You don\'t have permission to do that.');
		if ($this->request->is('post')) {
			if (isset($this->request->data['Tag']['request'])) $this->request->data['Tag'] = $this->request->data['Tag']['request'];
			if (!isset($this->request->data['Tag']['colour'])) $this->request->data['Tag']['colour'] = $this->Tag->random_color();
			if (isset($this->request->data['Tag']['id'])) unset($this->request->data['Tag']['id']);
			if ($this->Tag->save($this->request->data)) {
				if ($this->_isRest()) $this->redirect(array('action' => 'view', $this->Tag->id));
				$this->Session->setFlash('The tag has been saved.');
				$this->redirect(array('action' => 'index'));
			} else {
				if ($this->_isRest()) {
					$error_message = '';
					foreach ($this->Tag->validationErrors as $k => $v) $error_message .= '[' . $k . ']: ' . $v[0];
					throw new MethodNotAllowedException('Could not add the Tag. ' . $error_message);
				} else {
					$this->Session->setFlash('The tag could not be saved. Please, try again.');
				}
			}
		}
	}

	public function quickAdd() {
		if ((!$this->_isSiteAdmin() && !$this->userRole['perm_tag_editor']) || !$this->request->is('post')) throw new NotFoundException('You don\'t have permission to do that.');
		if (isset($this->request->data['Tag']['request'])) $this->request->data['Tag'] = $this->request->data['Tag']['request'];
		if ($this->Tag->quickAdd($this->request->data['Tag']['name'])) {
			$this->Session->setFlash('The tag has been saved.');
		} else {
			$this->Session->setFlash('The tag could not be saved. Please, try again.');
		}
		$this->redirect($this->referer());
	}

	public function edit($id) {
		if (!$this->_isSiteAdmin() && !$this->userRole['perm_tag_editor']) {
			throw new NotFoundException('You don\'t have permission to do that.');
		}
		$this->Tag->id = $id;
		if (!$this->Tag->exists()) {
			throw new NotFoundException('Invalid tag');
		}
		if ($this->request->is('post') || $this->request->is('put')) {
			$this->request->data['Tag']['id'] = $id;
			if (isset($this->request->data['Tag']['request'])) $this->request->data['Tag'] = $this->request->data['Tag']['request'];

			if ($this->Tag->save($this->request->data)) {
				if ($this->_isRest()) $this->redirect(array('action' => 'view', $id));
				$this->Session->setFlash('The Tag has been edited');
				$this->redirect(array('action' => 'index'));
			} else {
				if ($this->_isRest()) {
					$error_message = '';
					foreach ($this->Tag->validationErrors as $k => $v) $error_message .= '[' . $k . ']: ' . $v[0];
					throw new MethodNotAllowedException('Could not add the Tag. ' . $error_message);
				}
				$this->Session->setFlash('The Tag could not be saved. Please, try again.');
			}
		}
		$this->request->data = $this->Tag->read(null, $id);
	}

	public function delete($id) {
		if (!$this->_isSiteAdmin() && !$this->userRole['perm_tag_editor']) {
			throw new NotFoundException('You don\'t have permission to do that.');
		}
		if (!$this->request->is('post')) {
			throw new MethodNotAllowedException();
		}
		$this->Tag->id = $id;
		if (!$this->Tag->exists()) {
			throw new NotFoundException('Invalid tag');
		}
		if ($this->Tag->delete()) {
			if ($this->_isRest()) {
				$this->set('name', 'Tag deleted.');
				$this->set('message', 'Tag deleted.');
				$this->set('url', '/tags/delete/' . $id);
				$this->set('_serialize', array('name', 'message', 'url'));
			}
			$this->Session->setFlash(__('Tag deleted'));
		} else {
			if ($this->_isRest()) throw new MethodNotAllowedException('Could not delete the tag, or tag doesn\'t exist.');
			$this->Session->setFlash(__('Tag was not deleted'));
		}
		if (!$this->_isRest()) $this->redirect(array('action' => 'index'));
	}

	public function view($id) {
		if ($this->_isRest()) {
			$tag = $this->Tag->find('first', array(
					'conditions' => array('id' => $id),
					'recursive' => -1,
					'contain' => array('EventTag' => array('fields' => 'event_id'))
			));
			if (empty($tag)) throw MethodNotAllowedException('Invalid Tag');
			$eventIDs = array();
			if (empty($tag['EventTag'])) $tag['Tag']['count'] = 0;
			else {
				foreach ($tag['EventTag'] as $eventTag) {
					$eventIDs[] = $eventTag['event_id'];
				}
				$conditions = array('Event.id' => $eventIDs);
				if (!$this->_isSiteAdmin()) $conditions = array_merge(
						$conditions,
						array('OR' => array(
								array('AND' => array(
										array('Event.distribution >' => 0),
										array('Event.published =' => 1)
								)),
								array('Event.orgc_id' => $this->Auth->user('org_id'))
						)));
				$events = $this->Tag->EventTag->Event->find('all', array(
						'fields' => array('Event.id', 'Event.distribution', 'Event.orgc_id'),
						'conditions' => $conditions
				));
				$tag['Tag']['count'] = count($events);
			}
			unset($tag['EventTag']);
			$this->set('Tag', $tag['Tag']);
			$this->set('_serialize', 'Tag');
		} else throw new MethodNotAllowedException('This action is only for REST users.');

	}

	public function showEventTag($id) {
		$this->helpers[] = 'TextColour';
		$this->loadModel('EventTag');
		$tags = $this->EventTag->find('all', array(
				'conditions' => array(
						'event_id' => $id
				),
				'contain' => array('Tag'),
				'fields' => array('Tag.id', 'Tag.colour', 'Tag.name'),
		));
		$this->set('tags', $tags);
		$tags = $this->Tag->find('all', array('recursive' => -1, 'order' => array('Tag.name ASC')));
		$tagNames = array('None');
		foreach ($tags as $k => $v) {
			$tagNames[$v['Tag']['id']] = $v['Tag']['name'];
		}
		$this->set('allTags', $tagNames);
		$event = $this->Tag->EventTag->Event->find('first', array(
				'recursive' => -1,
				'fields' => array('Event.id', 'Event.orgc_id', 'Event.org_id', 'Event.user_id'),
				'conditions' => array('Event.id' => $id)
		));
		$this->set('event', $event);
		$this->layout = 'ajax';
		$this->render('/Events/ajax/ajaxTags');
	}

	public function viewTag($id) {
		$tag = $this->Tag->find('first', array(
				'conditions' => array(
						'id' => $id
				),
				'recursive' => -1,
		));
		$this->layout = null;
		$this->set('tag', $tag);
		$this->set('id', $id);
		$this->render('ajax/view_tag');
	}


	public function selectTaxonomy($event_id) {
		if (!$this->_isSiteAdmin() && !$this->userRole['perm_tagger']) throw new NotFoundException('You don\'t have permission to do that.');
		$favourites = $this->Tag->FavouriteTag->find('count', array('conditions' => array('FavouriteTag.user_id' => $this->Auth->user('id'))));
		$this->loadModel('Taxonomy');
		$options = $this->Taxonomy->find('list', array('conditions' => array('enabled' => true), 'fields' => array('namespace'), 'order' => array('Taxonomy.namespace ASC')));
		foreach ($options as $k => &$option) {
			$tags = $this->Taxonomy->getTaxonomyTags($k, false, true);
			if (empty($tags)) unset($options[$k]);
		}
		$this->set('event_id', $event_id);
		$this->set('options', $options);
		$this->set('favourites', $favourites);
		$this->render('ajax/taxonomy_choice');
	}

	public function selectTag($event_id, $taxonomy_id) {
		if (!$this->_isSiteAdmin() && !$this->userRole['perm_tagger']) throw new NotFoundException('You don\'t have permission to do that.');
		$this->loadModel('Taxonomy');
		$expanded = array();
		if ($taxonomy_id === '0') {
			$options = $this->Taxonomy->getAllTaxonomyTags(true);
			$expanded = $options;
		} else if ($taxonomy_id === 'favourites') {
			$tags = $this->Tag->FavouriteTag->find('all', array(
				'conditions' => array('FavouriteTag.user_id' => $this->Auth->user('id')),
				'recursive' => -1,
				'contain' => array('Tag.name')
			));
			foreach ($tags as $tag) {
				$options[$tag['FavouriteTag']['tag_id']] = $tag['Tag']['name'];
				$expanded = $options;
			}
		} else {
			$taxonomies = $this->Taxonomy->getTaxonomy($taxonomy_id);
			$options = array();
			foreach ($taxonomies['entries'] as &$entry) {
				if (!empty($entry['existing_tag']['Tag'])) {
					$options[$entry['existing_tag']['Tag']['id']] = $entry['existing_tag']['Tag']['name'];
					$expanded[$entry['existing_tag']['Tag']['id']] = $entry['expanded'];
				}
			}
		}
		$this->set('event_id', $event_id);
		$this->set('options', $options);
		$this->set('expanded', $expanded);
		$this->set('custom', $taxonomy_id == 0 ? true : false);
		$this->render('ajax/select_tag');
	}

	public function tagStatistics($percentage = false, $keysort = false) {
		$result = $this->Tag->EventTag->find('all', array(
				'recursive' => -1,
				'fields' => array('count(EventTag.id) as count', 'tag_id'),
				'contain' => array('Tag' => array('fields' => array('Tag.name'))),
				'group' => array('tag_id')
		));
		$tags = array();
		$taxonomies = array();
		$totalCount = 0;
		$this->loadModel('Taxonomy');
		$temp = $this->Taxonomy->listTaxonomies(array('enabled' => true));
		foreach ($temp as $t) {
			if ($t['enabled']) $taxonomies[$t['namespace']] = 0;
		}
		foreach ($result as $r) {
			if ($r['Tag']['name'] == null) continue;
			$tags[$r['Tag']['name']] = $r[0]['count'];
			$totalCount += $r[0]['count'];
			foreach ($taxonomies as $taxonomy => $count) {
				if (substr(strtolower($r['Tag']['name']), 0, strlen($taxonomy)) === strtolower($taxonomy)) $taxonomies[$taxonomy] += $r[0]['count'];
			}
		}
		if ($keysort === 'true') {
			ksort($tags, SORT_NATURAL | SORT_FLAG_CASE);
			ksort($taxonomies, SORT_NATURAL | SORT_FLAG_CASE);
		} else {
			arsort($tags);
			arsort($taxonomies);
		}
		if ($percentage === 'true') {
			foreach ($tags as $tag => &$count) {
				$count = round(100 * $count / $totalCount, 3) . '%';
			}
			foreach ($taxonomies as $taxonomy => &$count) {
				$count = round(100 * $count / $totalCount, 3) . '%';
			}
		}
		$results = array('tags' => $tags, 'taxonomies' => $taxonomies);
		$this->autoRender = false;
		$this->layout = false;
		$this->set('data', $results);
		$this->set('flags', JSON_PRETTY_PRINT);
		$this->response->type('json');
		$this->render('/Servers/json/simple');
	}
}
