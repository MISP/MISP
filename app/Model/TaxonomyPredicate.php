<?php
App::uses('AppModel', 'Model');

class TaxonomyPredicate extends AppModel
{
    public $useTable = 'taxonomy_predicates';

    public $recursive = -1;

    public $actsAs = array(
            'Containable',
    );

    public $validate = array(
        'value' => array(
            'rule' => array('stringNotEmpty'),
        ),
        'expanded' => array(
            'rule' => array('stringNotEmpty'),
        ),
    );

    public $hasMany = array(
            'TaxonomyEntry' => array(
                'dependent' => true
            )
    );

    public function beforeValidate($options = array())
    {
		if (empty($this->data['TaxonomyPredicate']['expanded'])) {
			$this->data['TaxonomyPredicate']['expanded'] = $this->data['TaxonomyPredicate']['value'];
		}
        parent::beforeValidate();
        return true;
    }
}
