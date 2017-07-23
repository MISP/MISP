<?php


namespace Model;

class TemplateTag extends AppModel {
	public $actsAs = array('Containable');
	public $belongsTo = array('Template', 'Tag');
}
