<?php

App::uses('AppController', 'Controller');

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
	
	public function index($id) {
		
	}
	
	public function edit($id) {
		
	}
	
	public function view($id) {
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
}
