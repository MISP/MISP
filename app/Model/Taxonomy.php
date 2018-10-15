<?php
App::uses('AppModel', 'Model');

class Taxonomy extends AppModel
{
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

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        return true;
    }

    public function update()
    {
        $directories = glob(APP . 'files' . DS . 'taxonomies' . DS . '*', GLOB_ONLYDIR);
        foreach ($directories as $k => $dir) {
            $dir = str_replace(APP . 'files' . DS . 'taxonomies' . DS, '', $dir);
            if ($dir === 'tools') {
                unset($directories[$k]);
            } else {
                $directories[$k] = $dir;
            }
        }
        $updated = array();
        foreach ($directories as $dir) {
            if (!file_exists(APP . 'files' . DS . 'taxonomies' . DS . $dir . DS . 'machinetag.json')) {
                continue;
            }
            $file = new File(APP . 'files' . DS . 'taxonomies' . DS . $dir . DS . 'machinetag.json');
            $vocab = json_decode($file->read(), true);
            if (isset($vocab['type'])) {
                if (is_array($vocab['type'])) {
                    if (!in_array('event', $vocab['type'])) {
                        continue;
                    }
                } else {
                    if ($vocab['type'] !== 'event') {
                        continue;
                    }
                }
            }
            $file->close();
            if (!isset($vocab['version'])) {
                $vocab['version'] = 1;
            }
            $current = $this->find('first', array(
                'conditions' => array('namespace' => $vocab['namespace']),
                'recursive' => -1,
                'fields' => array('version', 'enabled', 'namespace')
            ));
            if (empty($current) || $vocab['version'] > $current['Taxonomy']['version']) {
                $result = $this->__updateVocab($vocab, $current);
                if (is_numeric($result)) {
                    $updated['success'][$result] = array('namespace' => $vocab['namespace'], 'new' => $vocab['version']);
                    if (!empty($current)) {
                        $updated['success'][$result]['old'] = $current['Taxonomy']['version'];
                    }
                } else {
                    $updated['fails'][] = array('namespace' => $vocab['namespace'], 'fail' => json_encode($result));
                }
            }
        }
        return $updated;
    }

    private function __updateVocab($vocab, $current, $skipUpdateFields = array())
    {
        $enabled = 0;
        $taxonomy = array();
        if (!empty($current)) {
            if ($current['Taxonomy']['enabled']) {
                $enabled = 1;
            }
            $this->deleteAll(array('Taxonomy.namespace' => $current['Taxonomy']['namespace']));
        }
        $taxonomy['Taxonomy'] = array('namespace' => $vocab['namespace'], 'description' => $vocab['description'], 'version' => $vocab['version'], 'enabled' => $enabled);
        $predicateLookup = array();
        foreach ($vocab['predicates'] as $k => $predicate) {
            $taxonomy['Taxonomy']['TaxonomyPredicate'][$k] = $predicate;
            $predicateLookup[$predicate['value']] = $k;
        }
        if (!empty($vocab['values'])) {
            foreach ($vocab['values'] as $value) {
                if (empty($taxonomy['Taxonomy']['TaxonomyPredicate'][$predicateLookup[$value['predicate']]]['TaxonomyEntry'])) {
                    $taxonomy['Taxonomy']['TaxonomyPredicate'][$predicateLookup[$value['predicate']]]['TaxonomyEntry'] = $value['entry'];
                } else {
                    $taxonomy['Taxonomy']['TaxonomyPredicate'][$predicateLookup[$value['predicate']]]['TaxonomyEntry'] = array_merge($taxonomy['Taxonomy']['TaxonomyPredicate'][$predicateLookup[$value['predicate']]]['TaxonomyEntry'], $value['entry']);
                }
            }
        }
        $result = $this->saveAssociated($taxonomy, array('deep' => true));
        if ($result) {
            $this->__updateTags($this->id, $skipUpdateFields);
            return $this->id;
        }
        return $this->validationErrors;
    }

    private function __getTaxonomy($id, $options = array('full' => false, 'filter' => false))
    {
        $recursive = -1;
        if ($options['full']) {
            $recursive = 2;
        }
        $filter = false;
        if (isset($options['filter'])) {
            $filter = $options['filter'];
        }
        $taxonomy = $this->find('first', array(
                'recursive' => $recursive,
                'conditions' => array('Taxonomy.id' => $id)
        ));
        if (empty($taxonomy)) {
            return false;
        }
        $entries = array();
        foreach ($taxonomy['TaxonomyPredicate'] as $predicate) {
            if (isset($predicate['TaxonomyEntry']) && !empty($predicate['TaxonomyEntry'])) {
                foreach ($predicate['TaxonomyEntry'] as $entry) {
                    $temp = array('tag' => $taxonomy['Taxonomy']['namespace'] . ':' . $predicate['value'] . '="' . $entry['value'] . '"');
                    $temp['expanded'] = (!empty($predicate['expanded']) ? $predicate['expanded'] : $predicate['value']) . ': ' . (!empty($entry['expanded']) ? $entry['expanded'] : $entry['value']);
                    if (isset($entry['colour']) && !empty($entry['colour'])) {
                        $temp['colour'] = $entry['colour'];
                    }
					if (isset($entry['numerical_value']) && $entry['numerical_value'] !== null) {
						$temp['numerical_value'] = $entry['numerical_value'];
					}
                    $entries[] = $temp;
                }
            } else {
                $temp = array('tag' => $taxonomy['Taxonomy']['namespace'] . ':' . $predicate['value']);
                $temp['expanded'] = !empty($predicate['expanded']) ? $predicate['expanded'] : $predicate['value'];
                if (isset($predicate['colour']) && !empty($predicate['colour'])) {
                    $temp['colour'] = $predicate['colour'];
                }
				if (isset($predicate['numerical_value']) && $predicate['numerical_value'] !== null) {
					$temp['numerical_value'] = $predicate['numerical_value'];
				}
                $entries[] = $temp;
            }
        }
        $taxonomy = array('Taxonomy' => $taxonomy['Taxonomy']);
        if ($filter) {
            $namespaceLength = strlen($taxonomy['Taxonomy']['namespace']);
            foreach ($entries as $k => $entry) {
                if (strpos(substr(strtoupper($entry['tag']), $namespaceLength), strtoupper($filter)) === false) {
                    unset($entries[$k]);
                }
            }
        }
        $taxonomy['entries'] = $entries;
        return $taxonomy;
    }

    // returns all tags associated to a taxonomy
    // returns all tags not associated to a taxonomy if $inverse is true
    public function getAllTaxonomyTags($inverse = false, $user = false)
    {
        $this->Tag = ClassRegistry::init('Tag');
        $taxonomyIdList = $this->find('list', array('fields' => array('id')));
        $taxonomyIdList = array_keys($taxonomyIdList);
        $allTaxonomyTags = array();
        foreach ($taxonomyIdList as $taxonomy) {
            $allTaxonomyTags = array_merge($allTaxonomyTags, array_keys($this->getTaxonomyTags($taxonomy, true)));
        }
        $conditions = array();
        if ($user) {
            if (!$user['Role']['perm_site_admin']) {
                $conditions = array('Tag.org_id' => array(0, $user['org_id']));
                $conditions = array('Tag.user_id' => array(0, $user['id']));
            }
        }
        if (Configure::read('MISP.incoming_tags_disabled_by_default')) {
            $conditions['Tag.hide_tag'] = 0;
        }
        $allTags = $this->Tag->find(
            'list',
            array(
                'fields' => array('name'),
                'order' => array('UPPER(Tag.name) ASC'),
                'conditions' => $conditions
            )
        );
        foreach ($allTags as $k => $tag) {
            if ($inverse && in_array(strtoupper($tag), $allTaxonomyTags)) {
                unset($allTags[$k]);
            }
            if (!$inverse && !in_array(strtoupper($tag), $allTaxonomyTags)) {
                unset($allTags[$k]);
            }
        }
        return $allTags;
    }

    public function getTaxonomyTags($id, $uc = false, $existingOnly = false)
    {
        $taxonomy = $this->__getTaxonomy($id, array('full' => true, 'filter' => false));
        if ($existingOnly) {
            $this->Tag = ClassRegistry::init('Tag');
            $tags = $this->Tag->find('list', array('fields' => array('name'), 'order' => array('UPPER(Tag.name) ASC')));
            foreach ($tags as $key => $tag) {
                $tags[$key] = strtoupper($tag);
            }
        }
        $entries = array();
        if ($taxonomy) {
            foreach ($taxonomy['entries'] as $entry) {
                $searchTerm = $uc ? strtoupper($entry['tag']) : $entry['tag'];
                if ($existingOnly) {
                    if (in_array(strtoupper($entry['tag']), $tags)) {
                        $entries[$searchTerm] = $entry['expanded'];
                    }
                    continue;
                }
                $entries[$searchTerm] = $entry['expanded'];
            }
        }
        return $entries;
    }

    public function getTaxonomy($id, $options = array('full' => true))
    {
        $this->Tag = ClassRegistry::init('Tag');
        $taxonomy = $this->__getTaxonomy($id, $options);
        if (isset($options['full']) && $options['full']) {
            if (empty($taxonomy)) {
                return false;
            }
            $tags = $this->Tag->getTagsForNamespace($taxonomy['Taxonomy']['namespace']);
            if (isset($taxonomy['entries'])) {
                foreach ($taxonomy['entries'] as $key => $temp) {
                    $taxonomy['entries'][$key]['existing_tag'] = isset($tags[strtoupper($temp['tag'])]) ? $tags[strtoupper($temp['tag'])] : false;
                }
            }
        }
        return $taxonomy;
    }

    private function __updateTags($id, $skipUpdateFields = array())
    {
        $this->Tag = ClassRegistry::init('Tag');
        App::uses('ColourPaletteTool', 'Tools');
        $paletteTool = new ColourPaletteTool();
        $taxonomy = $this->__getTaxonomy($id, array('full' => true));
        $colours = $paletteTool->generatePaletteFromString($taxonomy['Taxonomy']['namespace'], count($taxonomy['entries']));
        $this->Tag = ClassRegistry::init('Tag');
        $tags = $this->Tag->getTagsForNamespace($taxonomy['Taxonomy']['namespace']);
        foreach ($taxonomy['entries'] as $k => $entry) {
            if (isset($tags[strtoupper($entry['tag'])])) {
                $temp = $tags[strtoupper($entry['tag'])];
                if (
					(!in_array('colour', $skipUpdateFields) && $temp['Tag']['colour'] != $colours[$k]) ||
					(!in_array('name', $skipUpdateFields) && $temp['Tag']['name'] !== $entry['tag']) ||
					(!in_array('numerical_value', $skipUpdateFields) && isset($entry['numerical_value']) && isset($temp['Tag']['numerical_value']) && $temp['Tag']['numerical_value'] !== $entry['numerical_value'])
				) {
                    if (!in_array('colour', $skipUpdateFields)) {
                        $temp['Tag']['colour'] = (isset($entry['colour']) && !empty($entry['colour'])) ? $entry['colour'] : $colours[$k];
                    }
                    if (!in_array('name', $skipUpdateFields)) {
                        $temp['Tag']['name'] = $entry['tag'];
                    }
					if (!in_array('numerical_value', $skipUpdateFields)) {
						$temp['Tag']['numerical_value'] = $entry['numerical_value'];
					}
                    $this->Tag->save($temp['Tag']);
                }
            }
        }
    }

    public function addTags($id, $tagList = false)
    {
        if ($tagList && !is_array($tagList)) {
            $tagList = array($tagList);
        }
        $this->Tag = ClassRegistry::init('Tag');
        App::uses('ColourPaletteTool', 'Tools');
        $paletteTool = new ColourPaletteTool();
        $taxonomy = $this->__getTaxonomy($id, array('full' => true));
        $tags = $this->Tag->getTagsForNamespace($taxonomy['Taxonomy']['namespace']);
        $colours = $paletteTool->generatePaletteFromString($taxonomy['Taxonomy']['namespace'], count($taxonomy['entries']));
        foreach ($taxonomy['entries'] as $k => $entry) {
            $colour = $colours[$k];
            if (isset($entry['colour']) && !empty($entry['colour'])) {
                $colour = $entry['colour'];
            }
            if ($tagList) {
                foreach ($tagList as $tagName) {
                    if ($tagName === $entry['tag']) {
                        if (isset($tags[strtoupper($entry['tag'])])) {
                            $this->Tag->quickEdit($tags[strtoupper($entry['tag'])], $tagName, $colour, 0);
                        } else {
                            $this->Tag->quickAdd($tagName, $colour);
                        }
                    }
                }
            } else {
                if (isset($tags[strtoupper($entry['tag'])])) {
                    $this->Tag->quickEdit($tags[strtoupper($entry['tag'])], $entry['tag'], $colour, 0);
                } else {
                    $this->Tag->quickAdd($entry['tag'], $colour);
                }
            }
        }
        return true;
    }

    public function disableTags($id, $tagList = false)
    {
        if ($tagList && !is_array($tagList)) {
            $tagList = array($tagList);
        }
        $this->Tag = ClassRegistry::init('Tag');
        $tags = array();
        if ($tagList) {
            $tags = $tagList;
        } else {
            $taxonomy = $this->__getTaxonomy($id, array('full' => true));
            foreach ($taxonomy['entries'] as $entry) {
                $tags[] = $entry['tag'];
            }
        }
        if (empty($tags)) {
            return true;
        }
        $tags = $this->Tag->find('all', array(
            'conditions' => array('Tag.name' => $tags, 'Tag.hide_tag' => 0),
            'recursive' => -1
        ));
        if (empty($tags)) {
            return true;
        }
        $this->Tag->disableTags($tags);
        return true;
    }

    public function listTaxonomies($options = array('full' => false, 'enabled' => false))
    {
        $recursive = -1;
        if (isset($options['full']) && $options['full']) {
            $recursive = 2;
        }
        $conditions = array();
        if (isset($options['enabled']) && $options['enabled']) {
            $conditions[] = array('Taxonomy.enabled' => 1);
        }
        $temp =  $this->find('all', array(
            'recursive' => $recursive,
            'conditions' => $conditions
        ));
        $taxonomies = array();
        foreach ($temp as $t) {
            $taxonomies[$t['Taxonomy']['namespace']] = $t['Taxonomy'];
        }
        return $taxonomies;
    }

    public function getTaxonomyForTag($tagName)
    {
        if (preg_match('/^[^:="]+:[^:="]+="[^:="]+"$/i', $tagName)) {
            $temp = explode(':', $tagName);
            $pieces = array_merge(array($temp[0]), explode('=', $temp[1]));
            $pieces[2] = trim($pieces[2], '"');
            $taxonomy = $this->find('first', array(
                'recursive' => -1,
                'conditions' => array('LOWER(Taxonomy.namespace)' => strtolower($pieces[0])),
                'contain' => array(
                    'TaxonomyPredicate' => array(
                        'conditions' => array(
                            'LOWER(TaxonomyPredicate.value)' => strtolower($pieces[1])
                        ),
                        'TaxonomyEntry' => array(
                            'conditions' => array(
                                'LOWER(TaxonomyEntry.value)' => strtolower($pieces[2])
                            )
                        )
                    )
                )
            ));
            return $taxonomy;
        } elseif (preg_match('/^[^:="]+:[^:="]+$/i', $tagName)) {
            $pieces = explode(':', $tagName);
            $taxonomy = $this->find('first', array(
                'recursive' => -1,
                'conditions' => array('LOWER(Taxonomy.namespace)' => strtolower($pieces[0])),
                'contain' => array(
                    'TaxonomyPredicate' => array(
                        'conditions' => array(
                            'LOWER(TaxonomyPredicate.value)' => strtolower($pieces[1])
                        )
                    )
                )
            ));
            return $taxonomy;
        } else {
            return false;
        }
    }
}
