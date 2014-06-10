<?php

App::uses('AppController', 'Controller');

/**
 * TemplateElements Controller
 *
 * @property TemplateElement $TemplateElements
*/

class TemplateElementsController extends AppController {
	public $components = array('Security' ,'RequestHandler');

	public $paginate = array(
			'limit' => 50,
			'order' => array(
					'TemplateElement.position' => 'asc'
			)
	);
	
	public function index($id) {
		
		//check permissions
		
		$template = $this->TemplateElement->Template->find('first', array(
			'recursive' => -1,
			'fields' => array('id', 'share', 'org'),
			'conditions' => array('id' => $id)
		));
		
		if (!empty($template) && !$this->_isSiteAdmin() && !$template['Template']['share'] && !$template['Template']['org']) throw new MethodNotAllowedException('Template not found or you are not authorised to view it.');
		
		$templateElements = $this->TemplateElement->find('all', array(
			'conditions' => array(
				'template_id' => $id,
			),
			'contain' => array(
				'TemplateElementAttribute',
				'TemplateElementText'
			),
			'order' => array('TemplateElement.position ASC')
		));
		foreach ($templateElements as &$e) {
			if (!empty($e['TemplateElementAttribute'])) {
				$e['TemplateElementAttribute'][0]['type'] = json_decode($e['TemplateElementAttribute'][0]['type']);
			}
		}
		$this->set('id', $id);
		$this->layout = 'ajaxTemplate';
		$this->set('elements', $templateElements);
		$this->render('ajax/ajaxIndex');
	}
	
	public function templateElementAddChoices($id) {
		
		//check permissions
		
		if (!$this->request->is('ajax')) Throw new MethodNotAllowedException('This action is for ajax requests only.');
		$this->set('id', $id);
		$this->layout = 'ajax';
		$this->render('ajax/template_element_add_choices');
	}
	
	public function templateElementAdd($type, $id) {
		
		//check permissions
		
		if (!$this->request->is('ajax')) Throw new MethodNotAllowedException('This action is for ajax requests only.');
		
		if ($this->request->is('get')) {
			$this->set('id', $id);
			$this->layout = 'ajaxTemplate';
			$this->render('ajax/template_element_add_' . $type);
		} else if ($this->request->is('post')) {
			$pos = $this->TemplateElement->lastPosition($id);
			//$capType = ucfirst($type);
			$this->TemplateElement->create();
			$templateElement = array(
				'TemplateElement' => array(
					'template_id' => $id,
					'position' => ++$pos,
					'element_definition' => $type
				),
			);
			if ($this->TemplateElement->save($templateElement)) {
				$this->request->data['TemplateElementText']['template_element_id'] = $this->TemplateElement->id;
				$this->TemplateElement->TemplateElementText->create();
				if ($this->TemplateElement->TemplateElementText->save($this->request->data)) {
					return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'Element successfully added to template.')), 'status' => 200));
				} else {
					$this->TemplateElement->delete($this->TemplateElement->id);
				}
			}
			return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'errors' => 'The element could not be added.')), 'status' => 200));
		}
	}
}
