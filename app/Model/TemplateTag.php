<?php

App::uses('AppModel', 'Model');

class TemplateTag extends AppModel
{
    public $actsAs = array('Containable');
    public $belongsTo = array('Template', 'Tag');
}
