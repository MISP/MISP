<?php
App::uses('AppModel', 'Model');

/**
 * @property TaxonomyPredicate $TaxonomyPredicate
 */
class Taxonomy extends AppModel
{
    public $useTable = 'taxonomies';

    public $recursive = -1;

    public $actsAs = array(
        'AuditLog',
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

    public function update()
    {
        $existing = $this->find('all', array(
            'recursive' => -1,
            'fields' => array('version', 'enabled', 'namespace')
        ));
        $existing = array_column(array_column($existing, 'Taxonomy'), null, 'namespace');

        $directories = glob(APP . 'files' . DS . 'taxonomies' . DS . '*', GLOB_ONLYDIR);
        $updated = array();
        foreach ($directories as $dir) {
            $dir = basename($dir);
            if ($dir === 'tools') {
                continue;
            }

            $file = new File(APP . 'files' . DS . 'taxonomies' . DS . $dir . DS . 'machinetag.json');
            if (!$file->exists()) {
                continue;
            }
            try {
                $vocab = $this->jsonDecode($file->read());
            } catch (Exception $e) {
                $updated['fails'][] = array('namespace' => $dir, 'fail' => "File machinetag.json is not valid JSON.");
                continue;
            }

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

            if (!isset($vocab['version'])) {
                $vocab['version'] = 1;
            }
            if (!isset($existing[$vocab['namespace']]) || $vocab['version'] > $existing[$vocab['namespace']]['version']) {
                $current = isset($existing[$vocab['namespace']]) ? $existing[$vocab['namespace']] : [];
                $result = $this->__updateVocab($vocab, $current);
                if (is_numeric($result)) {
                    $updated['success'][$result] = array('namespace' => $vocab['namespace'], 'new' => $vocab['version']);
                    if (!empty($current)) {
                        $updated['success'][$result]['old'] = $current['version'];
                    }
                } else {
                    $updated['fails'][] = array('namespace' => $vocab['namespace'], 'fail' => json_encode($result));
                }
            }
        }
        return $updated;
    }

    /**
     * @param array $vocab
     * @return int Taxonomy ID
     * @throws Exception
     */
    public function import(array $vocab)
    {
        foreach (['namespace', 'description', 'predicates'] as $requiredField) {
            if (!isset($vocab[$requiredField])) {
                throw new Exception("Required field '$requiredField' not provided.");
            }
        }
        if (!is_array($vocab['predicates'])) {
            throw new Exception("Field 'predicates' must be array.");
        }
        if (isset($vocab['values']) && !is_array($vocab['values'])) {
            throw new Exception("Field 'values' must be array.");
        }
        if (!isset($vocab['version'])) {
            $vocab['version'] = 1;
        }
        $current = $this->find('first', array(
            'conditions' => array('namespace' => $vocab['namespace']),
            'recursive' => -1,
            'fields' => array('version', 'enabled', 'namespace')
        ));
        $current = empty($current) ? [] : $current['Taxonomy'];
        $result = $this->__updateVocab($vocab, $current);
        if (is_array($result)) {
            throw new Exception('Could not save taxonomy because of validation errors: ' . json_encode($result));
        }
        return (int)$result;
    }

    private function __updateVocab(array $vocab, array $current)
    {
        $enabled = 0;
        if (!empty($current)) {
            if ($current['enabled']) {
                $enabled = 1;
            }
            $this->deleteAll(['Taxonomy.namespace' => $current['namespace']]);
        }
        $taxonomy = ['Taxonomy' => [
            'namespace' => $vocab['namespace'],
            'description' => $vocab['description'],
            'version' => $vocab['version'],
            'exclusive' => !empty($vocab['exclusive']),
            'enabled' => $enabled,
        ]];
        $predicateLookup = array();
        foreach ($vocab['predicates'] as $k => $predicate) {
            $taxonomy['Taxonomy']['TaxonomyPredicate'][$k] = $predicate;
            $predicateLookup[$predicate['value']] = $k;
        }
        if (!empty($vocab['values'])) {
            foreach ($vocab['values'] as $value) {
                $predicatePosition = $predicateLookup[$value['predicate']];
                if (empty($taxonomy['Taxonomy']['TaxonomyPredicate'][$predicatePosition]['TaxonomyEntry'])) {
                    $taxonomy['Taxonomy']['TaxonomyPredicate'][$predicatePosition]['TaxonomyEntry'] = $value['entry'];
                } else {
                    $taxonomy['Taxonomy']['TaxonomyPredicate'][$predicatePosition]['TaxonomyEntry'] = array_merge($taxonomy['Taxonomy']['TaxonomyPredicate'][$predicatePosition]['TaxonomyEntry'], $value['entry']);
                }
            }
        }
        $result = $this->saveAssociated($taxonomy, ['deep' => true]);
        if ($result) {
            $this->__updateTags($this->id);
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
        $taxonomy_params = array(
                'recursive' => -1,
                'contain' => array('TaxonomyPredicate' => array('TaxonomyEntry')),
                'conditions' => array('Taxonomy.id' => $id)
        );
        $taxonomy = $this->find('first', $taxonomy_params);
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
                    $temp['exclusive_predicate'] = $predicate['exclusive'];
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
                if (strpos(substr(mb_strtolower($entry['tag']), $namespaceLength), mb_strtolower($filter)) === false) {
                    unset($entries[$k]);
                }
            }
        }
        $taxonomy['entries'] = $entries;
        return $taxonomy;
    }

    // returns all tags associated to a taxonomy
    // returns all tags not associated to a taxonomy if $inverse is true
    public function getAllTaxonomyTags($inverse = false, $user = false, $full = false, $hideUnselectable = true)
    {
        $this->Tag = ClassRegistry::init('Tag');
        $taxonomyIdList = $this->find('column', array('fields' => array('Taxonomy.id')));
        $allTaxonomyTags = array();
        foreach ($taxonomyIdList as $taxonomy) {
            $allTaxonomyTags = array_merge($allTaxonomyTags, array_keys($this->getTaxonomyTags($taxonomy, true)));
        }
        $conditions = array();
        if ($user) {
            if (!$user['Role']['perm_site_admin']) {
                $conditions[] = array('Tag.org_id' => array(0, $user['org_id']));
                $conditions[] = array('Tag.user_id' => array(0, $user['id']));
            }
        }
        if (Configure::read('MISP.incoming_tags_disabled_by_default') || $hideUnselectable) {
            $conditions['Tag.hide_tag'] = 0;
        }
        if ($full) {
            $allTags = $this->Tag->find(
                'all',
                array(
                    'fields' => array('id', 'name', 'colour'),
                    'order' => array('UPPER(Tag.name) ASC'),
                    'conditions' => $conditions,
                    'recursive' => -1
                )
            );
        } else {
            $allTags = $this->Tag->find(
                'list',
                array(
                    'fields' => array('name'),
                    'order' => array('UPPER(Tag.name) ASC'),
                    'conditions' => $conditions
                )
            );
        }
        foreach ($allTags as $k => $tag) {
            if ($full) {
                $needle = $tag['Tag']['name'];
            } else {
                $needle = $tag;
            }
            if ($inverse) {
                if (in_array(strtoupper($needle), $allTaxonomyTags)) {
                    unset($allTags[$k]);
                } else {
                    $temp = explode(':', $needle);
                    if (count($temp) > 1) {
                        if ($temp[0] == 'misp-galaxy') {
                            unset($allTags[$k]);
                        }
                    }
                }
            }
            if (!$inverse && !in_array(strtoupper($needle), $allTaxonomyTags)) {
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
            $tagNames = array_column($taxonomy['entries'], 'tag');
            $tags = $this->Tag->getTagsByName($tagNames, false);
            if (isset($taxonomy['entries'])) {
                foreach ($taxonomy['entries'] as $key => $temp) {
                    if (isset($tags[strtoupper($temp['tag'])])) {
                        $existingTag = $tags[strtoupper($temp['tag'])];
                        $taxonomy['entries'][$key]['existing_tag'] = $existingTag;
                        // numerical_value is overridden at tag level. Propagate the override further up
                        if (isset($existingTag['Tag']['original_numerical_value'])) {
                            $taxonomy['entries'][$key]['original_numerical_value'] = $existingTag['Tag']['original_numerical_value'];
                            $taxonomy['entries'][$key]['numerical_value'] = $existingTag['Tag']['numerical_value'];
                        }
                    } else {
                        $taxonomy['entries'][$key]['existing_tag'] = false;
                    }
                }
            }
        }
        return $taxonomy;
    }

    private function __updateTags($id, $skipUpdateFields = array())
    {
        App::uses('ColourPaletteTool', 'Tools');
        $paletteTool = new ColourPaletteTool();
        $taxonomy = $this->__getTaxonomy($id, array('full' => true));
        $colours = $paletteTool->generatePaletteFromString($taxonomy['Taxonomy']['namespace'], count($taxonomy['entries']));
        $this->Tag = ClassRegistry::init('Tag');
        $tags = $this->Tag->getTagsForNamespace($taxonomy['Taxonomy']['namespace'], false);
        foreach ($taxonomy['entries'] as $k => $entry) {
            if (isset($tags[strtoupper($entry['tag'])])) {
                $temp = $tags[strtoupper($entry['tag'])];
                if (
                    (!in_array('colour', $skipUpdateFields) && $temp['Tag']['colour'] != $colours[$k]) ||
                    (!in_array('name', $skipUpdateFields) && $temp['Tag']['name'] !== $entry['tag']) ||
                    (
                        !in_array('numerical_value', $skipUpdateFields) &&
                        isset($entry['numerical_value']) && array_key_exists('numerical_value', $temp['Tag']) && // $temp['Tag']['num..'] may be null.
                        $temp['Tag']['numerical_value'] !== $entry['numerical_value']
                    )
                ) {
                    if (!in_array('colour', $skipUpdateFields)) {
                        $temp['Tag']['colour'] = (isset($entry['colour']) && !empty($entry['colour'])) ? $entry['colour'] : $colours[$k];
                    }
                    if (!in_array('name', $skipUpdateFields)) {
                        $temp['Tag']['name'] = $entry['tag'];
                    }
                    if (!in_array('numerical_value', $skipUpdateFields) && (isset($entry['numerical_value']) && $entry['numerical_value'] !== null)) {
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
        if (empty($taxonomy)) {
            return false;
        }
        $tags = $this->Tag->getTagsForNamespace($taxonomy['Taxonomy']['namespace']);
        $colours = $paletteTool->generatePaletteFromString($taxonomy['Taxonomy']['namespace'], count($taxonomy['entries']));
        foreach ($taxonomy['entries'] as $k => $entry) {
            $colour = $colours[$k];
            if (isset($entry['colour']) && !empty($entry['colour'])) {
                $colour = $entry['colour'];
            }
            $numerical_value = null;
            if (isset($entry['numerical_value'])) {
                $numerical_value = $entry['numerical_value'];
            }
            if ($tagList) {
                foreach ($tagList as $tagName) {
                    if ($tagName === $entry['tag']) {
                        if (isset($tags[strtoupper($entry['tag'])])) {
                            $this->Tag->quickEdit($tags[strtoupper($entry['tag'])], $tagName, $colour, 0, $numerical_value);
                        } else {
                            $this->Tag->quickAdd($tagName, $colour, $numerical_value);
                        }
                    }
                }
            } else {
                if (isset($tags[strtoupper($entry['tag'])])) {
                    $this->Tag->quickEdit($tags[strtoupper($entry['tag'])], $entry['tag'], $colour, 0, $numerical_value);
                } else {
                    $this->Tag->quickAdd($entry['tag'], $colour, $numerical_value);
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

    public function hideTags($id, $tagList = false)
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
                            $this->Tag->quickEdit($tags[strtoupper($entry['tag'])], $tagName, $colour, 1);
                        }
                    }
                }
            } else {
                if (isset($tags[strtoupper($entry['tag'])])) {
                    $this->Tag->quickEdit($tags[strtoupper($entry['tag'])], $entry['tag'], $colour, 1);
                }
            }
        }
        return true;
    }

    public function unhideTags($id, $tagList = false)
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
                        }
                    }
                }
            } else {
                if (isset($tags[strtoupper($entry['tag'])])) {
                    $this->Tag->quickEdit($tags[strtoupper($entry['tag'])], $entry['tag'], $colour, 0);
                }
            }
        }
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
            if (isset($options['full']) && $options['full']) {
                $t['Taxonomy']['TaxonomyPredicate'] = $t['TaxonomyPredicate'];
            }
            $taxonomies[$t['Taxonomy']['namespace']] = $t['Taxonomy'];
        }
        return $taxonomies;
    }

    public function getTaxonomyForTag($tagName, $metaOnly = false, $fullTaxonomy = false)
    {
        $splits = $this->splitTagToComponents($tagName);
        if ($splits === null) {
            return false; // not taxonomy tag
        }

        if (isset($splits['value'])) {
            $contain = array(
                'TaxonomyPredicate' => array(
                    'TaxonomyEntry' => array()
                )
            );
            if (!$fullTaxonomy) {
                $contain['TaxonomyPredicate']['conditions'] = array(
                    'LOWER(TaxonomyPredicate.value)' => mb_strtolower($splits['predicate']),
                );
                $contain['TaxonomyPredicate']['TaxonomyEntry']['conditions'] = array(
                    'LOWER(TaxonomyEntry.value)' => mb_strtolower($splits['value']),
                );
            }
            $taxonomy = $this->find('first', array(
                'recursive' => -1,
                'conditions' => array('LOWER(Taxonomy.namespace)' => mb_strtolower($splits['namespace'])),
                'contain' => $contain
            ));
            if ($metaOnly && !empty($taxonomy)) {
                return array('Taxonomy' => $taxonomy['Taxonomy']);
            }
            return $taxonomy;
        } else {
            $contain = array('TaxonomyPredicate' => array());
            if (!$fullTaxonomy) {
                $contain['TaxonomyPredicate']['conditions'] = array(
                    'LOWER(TaxonomyPredicate.value)' => mb_strtolower($splits['predicate'])
                );
            }
            $taxonomy = $this->find('first', array(
                'recursive' => -1,
                'conditions' => array('LOWER(Taxonomy.namespace)' => mb_strtolower($splits['namespace'])),
                'contain' => $contain
            ));
            if ($metaOnly && !empty($taxonomy)) {
                return array('Taxonomy' => $taxonomy['Taxonomy']);
            }
            return $taxonomy;
        }
    }

    /**
     * Remove the value for triple component tags or the predicate for double components tags
     * @param string $tagName
     * @return string
     */
    public function stripLastTagComponent($tagName)
    {
        $splits = $this->splitTagToComponents($tagName);
        if ($splits === null) {
            return '';
        }
        if (isset($splits['value'])) {
            return $splits['namespace'] . ':' . $splits['predicate'];
        }
        return $splits['namespace'];
    }

    public function checkIfNewTagIsAllowedByTaxonomy($newTagName, $tagNameList=array())
    {
        $newTagShortened = $this->stripLastTagComponent($newTagName);
        $prefixIsFree = true;
        foreach ($tagNameList as $tagName) {
            $tagShortened = $this->stripLastTagComponent($tagName);
            if ($newTagShortened == $tagShortened) {
                $prefixIsFree = false;
                break;
            }
        }
        if (!$prefixIsFree) {
            // at this point, we have a duplicated namespace(-predicate)
            $taxonomy = $this->getTaxonomyForTag($newTagName);
            if (!empty($taxonomy['Taxonomy']['exclusive'])) {
                return false; // only one tag of this taxonomy is allowed
            } elseif (!empty($taxonomy['TaxonomyPredicate'][0]['exclusive'])) {
                return false; // only one tag belonging to this predicate is allowed
            }
        }
        return true;
    }

    public function checkIfTagInconsistencies($tagList)
    {
        $eventTags = array();
        $localEventTags = array();
        foreach($tagList as $tag) {
            if ($tag['local'] == 0) {
                $eventTags[] = $tag['Tag']['name'];
            } else {
                $localEventTags[] = $tag['Tag']['name'];
            }
        }
        $tagConflicts = $this->getTagConflicts($eventTags);
        $localTagConflicts = $this->getTagConflicts($localEventTags);
        return array(
            'global' => $tagConflicts,
            'local' => $localTagConflicts
        );
    }

    public function getTagConflicts($tagNameList)
    {
        $potentiallyConflictingTaxonomy = array();
        $conflictingTaxonomy = array();
        foreach ($tagNameList as $tagName) {
            $tagShortened = $this->stripLastTagComponent($tagName);
            if (isset($potentiallyConflictingTaxonomy[$tagShortened])) {
                $potentiallyConflictingTaxonomy[$tagShortened]['taxonomy'] = $this->getTaxonomyForTag($tagName);
                $potentiallyConflictingTaxonomy[$tagShortened]['count']++;
            } else {
                $potentiallyConflictingTaxonomy[$tagShortened] = array(
                    'count' => 1
                );
            }
            $potentiallyConflictingTaxonomy[$tagShortened]['tagNames'][] = $tagName;
        }
        foreach ($potentiallyConflictingTaxonomy as $potTaxonomy) {
            if ($potTaxonomy['count'] > 1) {
                $taxonomy = $potTaxonomy['taxonomy'];
                if (isset($taxonomy['Taxonomy']['exclusive']) && $taxonomy['Taxonomy']['exclusive']) {
                    $conflictingTaxonomy[] = array(
                        'tags' => $potTaxonomy['tagNames'],
                        'taxonomy' => $taxonomy,
                        'conflict' => sprintf(__('Taxonomy `%s` is an exclusive Taxonomy'), $taxonomy['Taxonomy']['namespace'])
                    );
                } elseif (isset($taxonomy['TaxonomyPredicate'][0]['exclusive']) && $taxonomy['TaxonomyPredicate'][0]['exclusive']) {
                    $conflictingTaxonomy[] = array(
                        'tags' => $potTaxonomy['tagNames'],
                        'taxonomy' => $taxonomy,
                        'conflict' => sprintf(
                            __('Predicate `%s` is exclusive'),
                            $taxonomy['TaxonomyPredicate'][0]['value']
                        )
                    );
                }
            }
        }
        return $conflictingTaxonomy;
    }

    /**
     * @param string $tag
     * @return array|null
     */
    public function splitTagToComponents($tag)
    {
        preg_match('/^([^:="]+):([^:="]+)(="([^:="]+)")?$/i', $tag, $matches);
        if (empty($matches)) {
            return null; // tag is not in taxonomy format
        }
        $splits = [
            'namespace' => $matches[1],
            'predicate' => $matches[2],
        ];
        if (isset($matches[4])) {
            $splits['value'] = $matches[4];
        }
        return $splits;
    }
}
