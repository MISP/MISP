<?php

App::uses('AppModel', 'Model');

/**
 * Template Model
 *
*/
class Template extends AppModel {
	public $actsAs = array('Containable');
	public $hasMany = array(
		'TemplateTag', 
		'TemplateElement' => array(
			'order' => 'TemplateElement.position'
		)
	);
	
	public function trimElementPositions($id) {
		// permissions
		$this->id = $id;
		if (!$this->exists()) {
			throw new NotFoundException(__('Invalid template.'));
		}
	
		$template = $this->find('first', array(
				'conditions' => array('id' => $id),
				'recursive' => -1,
				'contain' => array(
						'TemplateElement' => array('id', 'template_id', 'position'),
				),
				'fields' => array('id', 'org'),
		));
		foreach ($template['TemplateElement'] as $k => &$element) {
			$element['position'] = $k+1;
		}
		$this->saveAll($template);
	}
	
	public function checkAuthorisation($id, $user, $write) {
		
		// fetch the bare template
		$template = $this->find('first', array(
			'conditions' => array('id' => $id),
			'recursive' => -1,
		));
		
		// if not found return false
		if (empty($template)) return false;
		
		//if the user is a site admin, return the template withoug question
		if ($user['Role']['perm_site_admin']) return $template;
		
		if ($write) {
			
			// if write access is requested, check if template belongs to user's org and whether the user is authorised to edit templates
			if ($user['org'] == $template['Template']['org'] && $user['Role']['perm_template']) return $template;
			return false;
		} else {
			
			// if read access is requested, check if the template belongs to the user's org or alternatively whether the template is shareable
			if ($user['org'] == $template['Template']['org'] || $template['Template']['share']) return $template;
			return false;
		}
	}
}
