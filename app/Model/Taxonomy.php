<?php
App::uses('AppModel', 'Model');
class Taxonomy extends AppModel{
	public $useTable = 'taxonomies';
	public $recursive = -1;
	public $actsAs = array(
			'Containable',
	);

	public $validate = array(
		'namespace' => array(
			'rule' => array('valueNotEmpty'),
		),
		'description' => array(
			'rule' => array('valueNotEmpty'),
		),
		'version' => array(
			'rule' => array('numeric'),
		)
	);
	
	public $hasMany = array(
			'TaxonomyPredicate' => array(
				'dependent' => true
			)
	);

	public function beforeValidate($options = array()) {
		parent::beforeValidate();
		return true;
	}
	
	public function update() {
		$directories = glob(APP . 'files' . DS . 'taxonomies' . DS . '*', GLOB_ONLYDIR);
		foreach ($directories as $k => &$dir) {
			$dir = str_replace(APP . 'files' . DS . 'taxonomies' . DS, '', $dir);
			if ($dir === 'tools') unset($directories[$k]);
		}
		$updated = array();
		foreach ($directories as &$dir) {
			$file = new File (APP . 'files' . DS . 'taxonomies' . DS . $dir . DS . 'machinetag.json');
			$vocab = json_decode($file->read(), true);
			$file->close();
			$current = $this->find('first', array(
				'conditions' => array('namespace' => $vocab['namespace']),
				'recursive' => -1,
				'fields' => array('version', 'enabled')
			));
			if (empty($current) || $vocab['version'] > $current['Taxonomy']['version']) {
				$result = $this->__updateVocab($vocab, $current);
				debug($result);
				if (is_numeric($result)) {
					$updated['success'][$result] = array('namespace' => $vocab['namespace'], 'new' => $vocab['version']);
					if (!empty($current)) $updated['success'][$result]['old'] = $current['Taxonomy']['version'];
				} else {
					$updated['fails'][] = array('namespace' => $vocab['namespace'], 'fail' => json_encode($result));
				}
			}
		}
		return $updated;
	}
	
	private function __updateVocab(&$vocab, &$current) {
		$enabled = false;
		$taxonomy = array();
		if (!empty($current)) {
			if ($current['Taxonomy']['enabled']) $enabled = true;
			$this->delete($current['Taxonomy']['id']);
		}
		$taxonomy['Taxonomy'] = array('namespace' => $vocab['namespace'], 'description' => $vocab['description'], 'version' => $vocab['version'], 'enabled' => $enabled);
		$predicateLookup = array();
		foreach ($vocab['predicates'] as $k => &$predicate) {
			$taxonomy['Taxonomy']['TaxonomyPredicate'][$k] = $predicate;
			$predicateLookup[$predicate['value']] = $k;
		}
		if (!empty($vocab['values'])) foreach ($vocab['values'] as &$value) $taxonomy['Taxonomy']['TaxonomyPredicate'][$predicateLookup[$value['predicate']]]['TaxonomyEntry'] = $value['entry'];
		$result = $this->saveAssociated($taxonomy, array('deep' => true));
		if ($result) return $this->id;
		return $this->validationErrors;
	}
	
	public function getTaxonomy($id, $options = array('full' => false)) {
		$this->Tag = ClassRegistry::init('Tag');
		$recursive = -1;
		if ($options['full']) $recursive = 2;
		$taxonomy = $this->find('first', array(
				'recursive' => $recursive,
				'conditions' => array('Taxonomy.id' => $id)
		));
		$tags_temp = $this->Tag->find('all', array(
			'recursive' => -1,
			'contain' => 'EventTag',
			'conditions' => array('name LIKE' => $taxonomy['Taxonomy']['namespace'] . '%'),
		));
		$tags = array();
		foreach ($tags_temp as &$temp) {
			$tags[$temp['Tag']['name']] = $temp;
		}
		unset($tags_temp);
		if (empty($taxonomy)) return false;
		$entries = array();
		foreach ($taxonomy['TaxonomyPredicate'] as &$predicate) {
			if (isset($predicate['TaxonomyEntry']) && !empty($predicate['TaxonomyEntry'])) {
				foreach ($predicate['TaxonomyEntry'] as &$entry) {
					$temp = array('tag' => $taxonomy['Taxonomy']['namespace'] . ':' . $predicate['value'] . '="' . $entry['value'] . '"');
					if (isset($predicate['expanded']) && isset($entry['expanded'])) $temp['expanded'] = $predicate['expanded'] . ': ' . $entry['expanded'];
					$temp['existing_tag'] = isset($tags[$temp['tag']]) ? $tags[$temp['tag']] : false;
					$entries[] = $temp;
				}
			} else {
				$temp = array('tag' => $taxonomy['Taxonomy']['namespace'] . ':' . $predicate['value']);
				$temp['existing_tag'] = isset($tags[$temp['tag']]) ? $tags[$temp['tag']] : false;
				if (isset($predicate['expanded'])) $temp['expanded'] = $predicate['expanded'];
				$entries[] = $temp;
			}
		}
		$taxonomy = array('Taxonomy' => $taxonomy['Taxonomy']);
		$taxonomy['entries'] = $entries;
		return $taxonomy;
	}
	
	public function listTaxonomies($options = array('full' => false, 'enabled' => false)) {
		$recursive = -1;
		if ($options['full']) $recursive = 2;
		return $this->find('all',  array(
			'recursive' => $recursive,
		));
	}
}