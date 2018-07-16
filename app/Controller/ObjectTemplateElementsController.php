<?php

App::uses('AppController', 'Controller');

class ObjectTemplateElementsController extends AppController {
	public $components = array('Security' ,'RequestHandler', 'Session');

	public $paginate = array(
			'limit' => 60,
			'order' => array(
					'ObjectTemplateElement.id' => 'desc'
			),
			'recursive' => -1
	);

	public function viewElements($id, $context = 'all') {
		$this->paginate['conditions'] = array('ObjectTemplateElement.object_template_id' => $id);
		$elements = $this->paginate();
		$this->set('list', $elements);
		$this->layout = 'ajax';
		$this->render('ajax/view_elements');
	}
}
