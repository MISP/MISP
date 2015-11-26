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
			if (!isset($vocab['version'])) $vocab['version'] = 1;
			$current = $this->find('first', array(
				'conditions' => array('namespace' => $vocab['namespace']),
				'recursive' => -1,
				'fields' => array('version', 'enabled')
			));
			if (empty($current) || $vocab['version'] > $current['Taxonomy']['version']) {
				$result = $this->__updateVocab($vocab, $current);
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
		if (!empty($vocab['values'])) foreach ($vocab['values'] as &$value) {
			if (empty($taxonomy['Taxonomy']['TaxonomyPredicate'][$predicateLookup[$value['predicate']]]['TaxonomyEntry'])) {
				$taxonomy['Taxonomy']['TaxonomyPredicate'][$predicateLookup[$value['predicate']]]['TaxonomyEntry'] = $value['entry'];
			} else {
				$taxonomy['Taxonomy']['TaxonomyPredicate'][$predicateLookup[$value['predicate']]]['TaxonomyEntry'] = array_merge($taxonomy['Taxonomy']['TaxonomyPredicate'][$predicateLookup[$value['predicate']]]['TaxonomyEntry'], $value['entry']);
			}
		}
		$result = $this->saveAssociated($taxonomy, array('deep' => true));
		if ($result) {
			$this->__updateTags($this->id);
			return $this->id;
		}
		return $this->validationErrors;
	}
	
	private function __getTaxonomy($id, $options = array('full' => false, 'filter' => false)) {
		$recursive = -1;
		if ($options['full']) $recursive = 2;
		$filter = false;
		if (isset($options['filter'])) $filter = $options['filter'];
		$taxonomy = $this->find('first', array(
				'recursive' => $recursive,
				'conditions' => array('Taxonomy.id' => $id)
		));
		if (empty($taxonomy)) return false;
		$entries = array();
		foreach ($taxonomy['TaxonomyPredicate'] as &$predicate) {
			if (isset($predicate['TaxonomyEntry']) && !empty($predicate['TaxonomyEntry'])) {
				foreach ($predicate['TaxonomyEntry'] as &$entry) {
					$temp = array('tag' => $taxonomy['Taxonomy']['namespace'] . ':' . $predicate['value'] . '="' . $entry['value'] . '"');
					$temp['expanded'] = (!empty($predicate['expanded']) ? $predicate['expanded'] : $predicate['value']) . ': ' . (!empty($entry['expanded']) ? $entry['expanded'] : $entry['value']);
					$entries[] = $temp;
				}
			} else {
				$temp = array('tag' => $taxonomy['Taxonomy']['namespace'] . ':' . $predicate['value']);
				$temp['expanded'] = !empty($predicate['expanded']) ? $predicate['expanded'] : $predicate['value'];
				$entries[] = $temp;
			}
		}
		$taxonomy = array('Taxonomy' => $taxonomy['Taxonomy']);
		if ($filter) {
			$namespaceLength = strlen($taxonomy['Taxonomy']['namespace']);
			foreach ($entries as $k => &$entry) {
				if (strpos(substr(strtoupper($entry['tag']), $namespaceLength), strtoupper($filter)) === false) unset($entries[$k]);
			}
		}
		$taxonomy['entries'] = $entries;
		return $taxonomy;
	}
	
	public function getTaxonomy($id, $options = array('full' => false)) {
		$this->Tag = ClassRegistry::init('Tag');
		$taxonomy = $this->__getTaxonomy($id, $options);
		if (empty($taxonomy)) return false;
		$tags = $this->Tag->getTagsForNamespace($taxonomy['Taxonomy']['namespace']);
		if (isset($taxonomy['entries'])) {
			foreach ($taxonomy['entries'] as &$temp) {
				$temp['existing_tag'] = isset($tags[strtoupper($temp['tag'])]) ? $tags[strtoupper($temp['tag'])] : false;
			}
		}
		return $taxonomy;
	}
	
	private function __updateTags($id) {
		$this->Tag = ClassRegistry::init('Tag');
		App::uses('ColourPaletteTool', 'Tools');
		$paletteTool = new ColourPaletteTool();
		$taxonomy = $this->__getTaxonomy($id, array('full' => true));
		$colours = $paletteTool->generatePaletteFromString($taxonomy['Taxonomy']['namespace'], count($taxonomy['entries']));
		$this->Tag = ClassRegistry::init('Tag');
		$tags = $this->Tag->getTagsForNamespace($taxonomy['Taxonomy']['namespace']);
		foreach ($taxonomy['entries'] as $k => &$entry) {
			if (isset($tags[strtoupper($entry['tag'])])) {
				$temp = $tags[strtoupper($entry['tag'])]; 
				if ($temp['Tag']['colour'] != $colours[$k] || $temp['Tag']['name'] !== $entry['tag']) {
					$temp['Tag']['colour'] = $colours[$k];
					$temp['Tag']['name'] = $entry['tag'];
					$this->Tag->save($temp['Tag']);
				}
			}
		}
	}
	
	public function addTags($id, $tagList) {
		if (!is_array($tagList)) $tagList = array($tagList);
		$this->Tag = ClassRegistry::init('Tag');
		App::uses('ColourPaletteTool', 'Tools');
		$paletteTool = new ColourPaletteTool();
		App::uses('ColourPaletteTool', 'Tools');
		$taxonomy = $this->__getTaxonomy($id, array('full' => true));
		$tags = $this->Tag->getTagsForNamespace($taxonomy['Taxonomy']['namespace']);
		$colours = $paletteTool->generatePaletteFromString($taxonomy['Taxonomy']['namespace'], count($taxonomy['entries']));
		foreach ($taxonomy['entries'] as $k => &$entry) {
			foreach ($tagList as $tagName) {
				if ($tagName === $entry['tag']) {
					if (isset($tags[strtoupper($entry['tag'])])) {
						$this->Tag->quickEdit($tags[strtoupper($entry['tag'])], $tagName, $colours[$k]);
					} else {
						$this->Tag->quickAdd($tagName, $colours[$k]);
					}
				}
			}
		}
		return true;
	}

	public function listTaxonomies($options = array('full' => false, 'enabled' => false)) {
		$recursive = -1;
		if ($options['full']) $recursive = 2;
		return $this->find('all',  array(
			'recursive' => $recursive,
		));
	}
}