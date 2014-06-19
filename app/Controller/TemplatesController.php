<?php

App::uses('AppController', 'Controller');
App::uses('ComplexTypeTool', 'Tools');

/**
 * Templates Controller
 *
 * @property Template $Templates
 */

class TemplatesController extends AppController {
	public $components = array('Security' ,'RequestHandler');

	public $paginate = array(
			'limit' => 50,
			'order' => array(
					'Template.id' => 'desc'
			)
	);

	public function beforeFilter() { // TODO REMOVE
		parent::beforeFilter();
		$this->Security->unlockedActions = array('saveElementSorting');
	}
	
	public function fetchFormFromTemplate($id) {
		
	}
	
	public function index() {
		$conditions = array();
		if (!$this->_isSiteAdmin()) {
			$conditions['OR'] = array('org' => $this->Auth->user('org'), 'share' => true);
		}
		if (!$this->_isSiteAdmin()) {
			$this->paginate = Set::merge($this->paginate,array(
					'conditions' =>
					array("OR" => array(
							array('org' => $this->Auth->user('org')),
							array('share' => true),
			))));
		}
		$this->set('list', $this->paginate());
	}
	
	public function edit($id) {
		$template = $this->Template->checkAuthorisation($id, $this->Auth->user(), true);
		if (!$this->_isSiteAdmin() && !$template) throw new MethodNotAllowedException('No template with the provided ID exists, or you are not authorised to edit it.');
		$this->set('mayModify', true);
		
		if ($this->request->is('post') || $this->request->is('put')) {
			$this->request->data['Template']['id'] = $id;
			
			unset($this->request->data['Template']['tagsPusher']);
			$tags = $this->request->data['Template']['tags'];
			unset($this->request->data['Template']['tags']);
			$this->request->data['Template']['org'] = $this->Auth->user('org');
			$this->Template->create();
			if ($this->Template->save($this->request->data)) {
				$id = $this->Template->id;
				$tagArray = json_decode($tags);
				$this->loadModel('TemplateTag');
				$oldTags = $this->TemplateTag->find('all', array(
					'conditions' => array('template_id' => $id),
					'recursive' => -1,
					'contain' => 'Tag'
				));

				$newTags = $this->TemplateTag->Tag->find('all', array(
					'recursive' => -1,
					'conditions' => array('name' => $tagArray)
				));
				
				foreach($oldTags as $k => $oT) {
					if (!in_array($oT['Tag'], $newTags)) $this->TemplateTag->delete($oT['TemplateTag']['id']); 
				}
				
				foreach($newTags as $k => $nT) {
					if (!in_array($nT['Tag'], $oldTags)) {
						$this->TemplateTag->create();
						$this->TemplateTag->save(array('TemplateTag' => array('template_id' => $id, 'tag_id' => $nT['Tag']['id'])));
					}
				}
				$this->redirect(array('action' => 'view', $this->Template->id));
			} else {
				throw new Exception('The template could not be edited.');
			}
		}
		$this->request->data = $template;

		// get all existing tags for the tag add dropdown menu
		$this->loadModel('Tags');
		$tags = $this->Tags->find('all');
		$tagArray = array();
		foreach ($tags as $tag) {
			$tagArray[$tag['Tags']['id']] = $tag['Tags']['name'];
		}
		
		//get all tags currently assigned to the event
		$currentTags = $this->Template->TemplateTag->find('all', array(
			'recursive' => -1,
			'contain' => 'Tag',
			'conditions' => array('template_id' => $id),
		));
		$this->set('currentTags', $currentTags);
		$this->set('id', $id);
		$this->set('template', $template);
		$this->set('tags', $tagArray);
		$this->set('tagInfo', $tags);
	}
	
	public function view($id) {
		if (!$this->_isSiteAdmin() && !$this->Template->checkAuthorisation($id, $this->Auth->user(), false)) throw new MethodNotAllowedException('No template with the provided ID exists, or you are not authorised to see it.');
		if ($this->Template->checkAuthorisation($id, $this->Auth->user(), true)) $this->set('mayModify', true);
		else $this->set('mayModify', false);
		$template = $this->Template->find('first', array(
			'conditions' => array(
				'id' => $id,
			),
			'contain' => array(
				'TemplateElement',
				'TemplateTag' => array(
					'Tag',
				),
			),
		));
		if (empty($template)) throw new NotFoundException('No template with the provided ID exists, or you are not authorised to see it.');
		$tagArray = array();
		foreach($template['TemplateTag'] as $tt) {
			$tagArray[] = $tt;
		}
		$this->set('id', $id);
		$this->set('template', $template);
	}
	
	public function add() {
		if ($this->request->is('post')) {
			unset($this->request->data['Template']['tagsPusher']);
			$tags = $this->request->data['Template']['tags'];
			unset($this->request->data['Template']['tags']);
			$this->request->data['Template']['org'] = $this->Auth->user('org');
			$this->Template->create();
			if ($this->Template->save($this->request->data)) {
				$id = $this->Template->id;
				$tagArray = json_decode($tags);
				$this->loadModel('TemplateTag');
				$this->loadModel('Tag');
				foreach ($tagArray as $t) {
					$tag = $this->Tag->find('first', array(
						'conditions' => array('name' => $t),
						'fields' => array('id', 'name'),
						'recursive' => -1,
					));
					$this->TemplateTag->create();
					$this->TemplateTag->save(array('TemplateTag' => array('template_id' => $id, 'tag_id' => $tag['Tag']['id'])));
				}
				$this->redirect(array('action' => 'view', $this->Template->id));
			} else {
				throw new Exception('The template could not be created.');
			}
		}
		$this->loadModel('Tags');
		$tags = $this->Tags->find('all');
		$tagArray = array();
		foreach ($tags as $tag) {
			$tagArray[$tag['Tags']['id']] = $tag['Tags']['name'];
		}
		$this->set('tags', $tagArray);
		$this->set('tagInfo', $tags);
	}
	
	public function saveElementSorting() {
		// check if user can edit the template
		$this->autoRender = false;
		$this->request->onlyAllow('ajax');
		$orderedElements = $this->request->data;
		foreach($orderedElements as &$e) {
			$e = ltrim($e, 'id_');
		}
		$extractedIds = array();
		foreach ($orderedElements as $element) $extractedIds[] = $element;
		$template_id = $this->Template->TemplateElement->find('first', array(
			'conditions' => array('id' => $extractedIds),
			'recursive' => -1,
			'fields' => array('id', 'template_id'),
		));
		
		if (!$this->_isSiteAdmin() && !$this->Template->checkAuthorisation($template_id['TemplateElement']['template_id'], $this->Auth->user(), true)) return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'You are not authorised to do that.')), 'status' => 200));
		
		$elements = $this->Template->TemplateElement->find('all', array(
				'conditions' => array('template_id' => $template_id['TemplateElement']['template_id']),
				'recursive' => -1,
		));
		if (empty($elements)) return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Something went wrong, the supplied template elements don\'t exist, or you are not eligible to edit them.')),'status'=>200));
		if (count($elements) != count($orderedElements)) return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Incomplete template element list passed as argument. Expecting ' . count($elements) . ' elements, only received positions for ' . count($orderedElements) . '.')),'status'=>200));
		$template_id = $elements[0]['TemplateElement']['template_id'];
		
		foreach ($elements as &$e) {
			if ($template_id !== $e['TemplateElement']['template_id']) return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Cannot sort template elements belonging to separate templates. You should never see this message during legitimate use.')),'status'=>200));
			foreach ($orderedElements as $k => $orderedElement) {
				if ($orderedElement == $e['TemplateElement']['id']) {
					$e['TemplateElement']['position'] = $k+1;
				}
			}
		}
		$this->Template->TemplateElement->saveMany($elements);
		return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'Elements repositioned.')),'status'=>200));
	}
	
	public function delete($id) {
		
	}
	

	public function templateChoices($id) {
		$this->loadModel('Event');
		$event = $this->Event->find('first' ,array(
				'conditions' => array('id' => $id),
				'recursive' => -1,
				'fields' => array('orgc', 'id'),
		));
		if (empty($event) || (!$this->_isSiteAdmin() && $event['Event']['orgc'] != $this->Auth->user('org'))) throw new MethodNotFoundException('Event not found or you are not authorised to edit it.');
	
		$conditions = array();
		if (!$this->_isSiteAdmin) {
			$conditions['OR'] = array('Template.org' => $this->Auth->user('org'), 'Template.share' => true);
		}
		$templates = $this->Template->find('all', array(
				'recursive' => -1,
				'conditions' => $conditions
		));
		$this->set('templates', $templates);
		$this->set('id', $id);
		$this->render('ajax/template_choices');
	}
	
	public function populateEventFromTemplate($template_id, $event_id) {
		$template = $this->Template->find('first', array(
			'conditions' => array('Template.id' => $template_id),
			'contain' => array(
				'TemplateElement' => array(
					'TemplateElementAttribute',
					'TemplateElementText',
					'TemplateElementFile'	
				),
				'TemplateTag' => array(
					'Tag'
				)
			),
		));
		$this->loadModel('Event');
		$event = $this->Event->find('first', array(
			'conditions' => array('id' => $event_id),
			'recursive' => -1,
			'fields' => array('id', 'orgc', 'distribution'),
		));
		if ($this->request->is('post')) {
			if (!isset($this->request->data['Template']['attributes'])) {
				$result = array();
				$errors = array();
				$attributes = array();
				foreach ($template['TemplateElement'] as $element) {
					if ($element['element_definition'] == 'attribute') {
						$result = $this->_resolveElementAttribute($element['TemplateElementAttribute'][0], $this->request->data['Template']['value_' . $element['id']]);
						if ($result['errors']) {
							$errors[$element['id']] = $result['errors'];
						} else {
							foreach ($result['attributes'] as &$a) {
								$a['event_id'] = $event_id;
								$a['distribution'] = $event['Event']['distribution'];
								$test = $this->Event->Attribute->checkForvalidationIssues(array('Attribute' => $a));
								if ($test) {
									foreach ($test['value'] as $e) {
										$errors[$element['id']] = $e;
									}
								} else {
									$attributes[] = $a;
								}
							}
						}
					} else if ($element['element_definition'] == 'file') {
						//$result = $this->_resolveElementFile($element['TemplateElementFile'][0], $this->request->data['Template']['value_' . $element['id']]);
					}
				}
				if (empty($errors)) {
					$this->set('template', $this->request->data);
					$this->set('attributes', $attributes);
					$this->set('distributionLevels', $this->Event->distributionLevels);
					$this->render('populate_event_from_template_attributes');
				} else {
					$this->set('template', $this->request->data);
					$this->set('errors', $errors);
					$this->set('templateData', $template);
					$this->loadModel('Attribute');
					$this->set('validTypeGroups', $this->Attribute->validTypeGroups);
				}
			} else {
				$attributes = unserialize($this->request->data['Template']['attributes']);
				$this->loadModel('Attribute');
				$fails = 0;
				foreach($attributes as $k => $attribute) {
					$this->Attribute->create();
					if (!$this->Attribute->save(array('Attribute' => $attribute))) $fails++;
				}
				if ($fails == 0) $this->Session->setFlash(__('Event populated, ' . $k . ' attributes successfully created.'));
				else $this->Session->setFlash(__('Event populated, but ' . $fails . ' attributes could not be saved.'));
				$this->redirect(array('controller' => 'events', 'action' => 'view', $event_id));
			}
		} else {
			$this->set('templateData', $template);
			$this->loadModel('Attribute');
			$this->set('validTypeGroups', $this->Attribute->validTypeGroups);
		}
	}
	
	private function _resolveElementAttribute($element, $value) {
		$attributes = array();
		$results = array();
		$errors=null;
		if (!empty($value)) {
			if ($element['batch']) {
				$values = explode("\n", $value);
				foreach ($values as $v) {
					$v = trim($v);
					$attributes[] = $this->_createAttribute($element, $v);
				}
			} else {
				$attributes[] = $this->_createAttribute($element, trim($value));
			}
			foreach ($attributes as $att) {
				if (isset($att['multi'])) {
					foreach ($att['multi'] as $a) {
						$results[] = $a;
					}
				} else {
					$results[] = $att;
				}
			}
		} else {
			if ($element['mandatory']) $errors = 'This field is mandatory.';
		}
		return array('attributes' => $results, 'errors' => $errors);
	}
	
	private function _createAttribute($element, $value) {
		$attribute = array(
			'comment' => $element['name'],
			'to_ids' => $element['to_ids'],
			'category' => $element['category'],	
			'value' => $value,
		);
		if ($element['complex']) {
			$complexTypeTool = new ComplexTypeTool();
			$result = $complexTypeTool->checkComplexRouter($value, ucfirst($element['type']));
			if (isset($result['multi'])) {
				$temp = $attribute;
				$attribute = array();
				foreach($result['multi'] as $k => $r) {
					$attribute['multi'][] = $temp;
					$attribute['multi'][$k]['type'] = $r['type'];
					$attribute['multi'][$k]['value'] = $r['value'];
				}
			} else if ($result != false) {
				$attribute['type'] = $result['type'];
				$attribute['value'] = $result['value'];
			} else {
				return false;
			}
		} else {
			$attribute['type'] = $element['type'];
		}
		return $attribute;
	}
	
	private function _resolveElementFile($element, $value) {
	
	}
}
