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
		$this->loadModel('Attribute');
		$this->set('validTypeGroups', $this->Attribute->validTypeGroups);
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
		$ModelType = 'TemplateElement' . ucfirst($type);
		//check permissions
		
		if (!$this->request->is('ajax')) Throw new MethodNotAllowedException('This action is for ajax requests only.');
		
		if ($this->request->is('get')) {
			$this->set('id', $id);
			if ($type == 'attribute') {
				$this->loadModel('Attribute');
				// combobox for types
				$types = array_keys($this->Attribute->typeDefinitions);
				$types = $this->_arrayToValuesIndexArray($types);
				$this->set('types', $types);
				// combobos for categories
				$categories = $this->Attribute->validate['category']['rule'][1];
				array_pop($categories);
				$categories = $this->_arrayToValuesIndexArray($categories);
				$this->set('categories', compact('categories'));
				$this->set('attrDescriptions', $this->Attribute->fieldDescriptions);
				$this->set('typeDefinitions', $this->Attribute->typeDefinitions);
				$categoryDefinitions = $this->Attribute->categoryDefinitions;
				foreach ($categoryDefinitions as $k => &$catDef) {
					foreach ($catDef['types'] as $l => $t) {
						if ($type == 'malware-sample' || $t == 'attachment') {
							array_splice($catDef['types'], $l, 1);
						}
					}
				}
				$this->set('categoryDefinitions', $this->Attribute->categoryDefinitions);
				$this->set('validTypeGroups', $this->Attribute->validTypeGroups);
				$this->set('typeGroupCategoryMapping', $this->Attribute->typeGroupCategoryMapping);
			}
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
			$errorMessage = 'The element could not be added.';
			if ($this->TemplateElement->save($templateElement)) {
				$this->request->data[$ModelType]['template_element_id'] = $this->TemplateElement->id;
				$this->TemplateElement->$ModelType->create();
				if ($this->TemplateElement->$ModelType->save($this->request->data)) {
					return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'Element successfully added to template.')), 'status' => 200));
				} else {
					$this->TemplateElement->delete($this->TemplateElement->id);
					$errorMessage = $this->TemplateElement->$ModelType->validationErrors;
				}
			} else {
				$errorMessage = $this->TemplateElement->validationErrors;
			}
			return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => $errorMessage)), 'status' => 200));
		}
	}
}
