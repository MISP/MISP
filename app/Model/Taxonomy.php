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

    private $__taxonomyConflicts = [];

    public function update($force = false)
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
            if ($dir === 'tools' || $dir === 'mapping') {
                continue;
            }

            $machineTagPath = APP . 'files' . DS . 'taxonomies' . DS . $dir . DS . 'machinetag.json';

            try {
                $vocab = FileAccessTool::readJsonFromFile($machineTagPath);
            } catch (Exception $e) {
                $updated['fails'][] = ['namespace' => $dir, 'fail' => $e->getMessage()];
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
                $current = $existing[$vocab['namespace']] ?? [];
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

        if (!empty($updated['success'])) {
            $this->cleanupCache();
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
            'fields' => array('version', 'enabled', 'namespace', 'highlighted')
        ));
        $current = empty($current) ? [] : $current['Taxonomy'];
        $result = $this->__updateVocab($vocab, $current);
        if (is_array($result)) {
            throw new Exception('Could not save taxonomy because of validation errors: ' . json_encode($result));
        }
        $this->cleanupCache();
        return (int)$result;
    }

    /**
     * @throws Exception
     */
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
            'highlighted' => !empty($vocab['highlighted']),
        ]];
        $predicateLookup = array();
        foreach ($vocab['predicates'] as $k => $predicate) {
            $taxonomy['Taxonomy']['TaxonomyPredicate'][$k] = $predicate;
            $predicateLookup[$predicate['value']] = $k;
        }
        if (!empty($vocab['values'])) {
            foreach ($vocab['values'] as $value) {
                if (!isset($predicateLookup[$value['predicate']])) {
                    throw new Exception("Invalid taxonomy `{$vocab['namespace']}` provided. Predicate `{$value['predicate']}` is missing.");
                }
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

    /**
     * @param int|string $id Taxonomy ID or namespace
     * @param string|boolean $filter String to filter to apply to the tags
     * @return array|false
     */
    private function __getTaxonomy($id, $filter = false)
    {
        if (!is_numeric($id)) {
            $conditions = ['Taxonomy.namespace' => trim(mb_strtolower($id))];
        } else {
            $conditions = ['Taxonomy.id' => $id];
        }
        $taxonomy_params = array(
            'recursive' => -1,
            'contain' => array('TaxonomyPredicate' => array('TaxonomyEntry')),
            'conditions' => $conditions
        );
        $taxonomy = $this->find('first', $taxonomy_params);
        if (empty($taxonomy)) {
            return false;
        }
        $entries = array();
        foreach ($taxonomy['TaxonomyPredicate'] as $predicate) {
            if (isset($predicate['TaxonomyEntry']) && !empty($predicate['TaxonomyEntry'])) {
                foreach ($predicate['TaxonomyEntry'] as $entry) {
                    $temp = [
                        'tag' => $taxonomy['Taxonomy']['namespace'] . ':' . $predicate['value'] . '="' . $entry['value'] . '"',
                        'expanded' => (!empty($predicate['expanded']) ? $predicate['expanded'] : $predicate['value']) . ': ' . (!empty($entry['expanded']) ? $entry['expanded'] : $entry['value']),
                        'exclusive_predicate' => $predicate['exclusive'],
                    ];
                    if (!empty($entry['description'])) {
                        $temp['description'] = $entry['description'];
                    }
                    if (!empty($entry['colour'])) {
                        $temp['colour'] = $entry['colour'];
                    }
                    if (isset($entry['numerical_value'])) {
                        $temp['numerical_value'] = $entry['numerical_value'];
                    }
                    if (empty($filter) || mb_strpos(mb_strtolower($temp['tag']), mb_strtolower($filter)) !== false) {
                        $entries[] = $temp;
                    }
                }
            } else {
                $temp = [
                    'tag' => $taxonomy['Taxonomy']['namespace'] . ':' . $predicate['value'],
                    'expanded' => !empty($predicate['expanded']) ? $predicate['expanded'] : $predicate['value']
                ];
                if (!empty($predicate['description'])) {
                    $temp['description'] = $predicate['description'];
                }
                if (!empty($predicate['colour'])) {
                    $temp['colour'] = $predicate['colour'];
                }
                if (isset($predicate['numerical_value'])) {
                    $temp['numerical_value'] = $predicate['numerical_value'];
                }
                if (empty($filter) || mb_strpos(mb_strtolower($temp['tag']), mb_strtolower($filter)) !== false) {
                    $entries[] = $temp;
                }
            }
        }
        $taxonomy = [
            'Taxonomy' => $taxonomy['Taxonomy'],
            'entries' => $entries,
        ];
        return $taxonomy;
    }

    /**
     * Returns all tags associated to a taxonomy
     * Returns all tags not associated to a taxonomy if $inverse is true
     * @param bool $inverse
     * @param false|array $user
     * @param bool $full
     * @param bool $hideUnselectable
     * @param bool $local_tag
     * @return array|int|null
     */
    public function getAllTaxonomyTags($inverse = false, $user = false, $full = false, $hideUnselectable = true, $local_tag = false)
    {
        $taxonomies = $this->find('all', [
            'fields' => ['namespace'],
            'recursive' => -1,
            'contain' => ['TaxonomyPredicate' => [
                'fields' => ['value'],
                'TaxonomyEntry' => ['fields' => ['value']]],
            ],
        ]);

        $allTaxonomyTags = [];
        foreach ($taxonomies as $taxonomy) {
            $namespace = $taxonomy['Taxonomy']['namespace'];
            foreach ($taxonomy['TaxonomyPredicate'] as $predicate) {
                if (isset($predicate['TaxonomyEntry']) && !empty($predicate['TaxonomyEntry'])) {
                    foreach ($predicate['TaxonomyEntry'] as $entry) {
                        $tag = $namespace . ':' . $predicate['value'] . '="' . $entry['value'] . '"';
                        $allTaxonomyTags[mb_strtolower($tag)] = true;
                    }
                } else {
                    $tag = $namespace . ':' . $predicate['value'];
                    $allTaxonomyTags[mb_strtolower($tag)] = true;
                }
            }
        }

        $this->Tag = ClassRegistry::init('Tag');

        $conditions = ['Tag.is_galaxy' => 0];
        if ($user && !$user['Role']['perm_site_admin']) {
            $conditions[] = array('Tag.org_id' => array(0, $user['org_id']));
            $conditions[] = array('Tag.user_id' => array(0, $user['id']));
        }
        if (Configure::read('MISP.incoming_tags_disabled_by_default') || $hideUnselectable) {
            $conditions['Tag.hide_tag'] = 0;
        }
        // If the tag is to be added as global, we filter out the local_only tags
        if (!$local_tag) {
            $conditions['Tag.local_only'] = 0;
        }
        if ($full) {
            $allTags = $this->Tag->find('all', [
                'fields' => array('id', 'name', 'colour'),
                'order' => array('UPPER(Tag.name) ASC'),
                'conditions' => $conditions,
                'recursive' => -1
            ]);
        } else {
            $allTags = $this->Tag->find('list', [
                'fields' => array('name'),
                'order' => array('UPPER(Tag.name) ASC'),
                'conditions' => $conditions
            ]);
        }
        foreach ($allTags as $k => $tag) {
            $needle = $full ? $tag['Tag']['name'] : $tag;
            if ($inverse) {
                if (isset($allTaxonomyTags[mb_strtolower($needle)])) {
                    unset($allTags[$k]);
                }
            }
            if (!$inverse && !isset($allTaxonomyTags[mb_strtolower($needle)])) {
                unset($allTags[$k]);
            }
        }
        return $allTags;
    }

    public function getTaxonomyTags($id, $upperCase = false, $existingOnly = false)
    {
        $taxonomy = $this->__getTaxonomy($id);
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
                $searchTerm = $upperCase ? strtoupper($entry['tag']) : $entry['tag'];
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

    /**
     * @param int|string $id Taxonomy ID or namespace
     * @param bool $full Add tag information to entries
     * @param string|boolean $filter String filter to apply to the tag names
     * @return array|false
     */
    public function getTaxonomy($id, $full = true, $filter = false)
    {
        $taxonomy = $this->__getTaxonomy($id, $filter);
        if (empty($taxonomy)) {
            return false;
        }
        if ($full) {
            $this->Tag = ClassRegistry::init('Tag');
            $tagNames = array_column($taxonomy['entries'], 'tag');
            $tags = $this->Tag->getTagsByName($tagNames, false);
            foreach ($taxonomy['entries'] as $key => $temp) {
                $tagLower = mb_strtolower($temp['tag']);
                if (isset($tags[$tagLower])) {
                    $existingTag = $tags[$tagLower];
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
        return $taxonomy;
    }

    private function __updateTags($id, $skipUpdateFields = array())
    {
        App::uses('ColourPaletteTool', 'Tools');
        $paletteTool = new ColourPaletteTool();
        $taxonomy = $this->__getTaxonomy($id);
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
        $taxonomy = $this->__getTaxonomy($id);
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
                    if ($tagName === $entry['tag'] || $tagName === h($entry['tag'])) {
                        if (isset($tags[strtoupper($entry['tag'])])) {
                            $this->Tag->quickEdit($tags[strtoupper($entry['tag'])], $entry['tag'], $colour, 0, $numerical_value);
                        } else {
                            $this->Tag->quickAdd($entry['tag'], $colour, $numerical_value);
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
            $taxonomy = $this->__getTaxonomy($id);
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
        $taxonomy = $this->__getTaxonomy($id);
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
        $taxonomy = $this->__getTaxonomy($id);
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
        $temp = $this->find('all', array(
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

    private function cleanupCache()
    {
        RedisTool::deleteKeysByPattern(RedisTool::init(), "misp:taxonomies_cache:*");
    }

    /**
     * @param string $tagName
     * @param bool $fullTaxonomy
     * @return array|false
     * @throws JsonException
     * @throws RedisException
     */
    public function getTaxonomyForTag($tagName, $fullTaxonomy = false)
    {
        $splits = $this->splitTagToComponents($tagName);
        if ($splits === null) {
            return false; // not a taxonomy tag
        }
        $key = "misp:taxonomies_cache:tagName=$tagName&fullTaxonomy=$fullTaxonomy";

        try {
            $redis = RedisTool::init();
            $taxonomy = RedisTool::deserialize(RedisTool::decompress($redis->get($key)));
            if (is_array($taxonomy)) {
                return $taxonomy;
            }
        } catch (Exception $e) {
            // ignore
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
        } else {
            $contain = array('TaxonomyPredicate' => array());
            if (!$fullTaxonomy) {
                $contain['TaxonomyPredicate']['conditions'] = array(
                    'LOWER(TaxonomyPredicate.value)' => mb_strtolower($splits['predicate'])
                );
            }
        }

        $taxonomy = $this->find('first', array(
            'recursive' => -1,
            'conditions' => array('LOWER(Taxonomy.namespace)' => mb_strtolower($splits['namespace'])),
            'contain' => $contain
        ));

        if (isset($redis)) {
            $redis->setex($key, 1800, RedisTool::compress(RedisTool::serialize($taxonomy)));
        }

        return $taxonomy;
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

    /**
     * @param string $newTagName
     * @param array $tagNameList
     * @return bool
     */
    public function checkIfNewTagIsAllowedByTaxonomy($newTagName, array $tagNameList=array())
    {
        $newTagShortened = $this->stripLastTagComponent($newTagName);
        $prefixIsFree = true;
        foreach ($tagNameList as $tagName) {
            $tagShortened = $this->stripLastTagComponent($tagName);
            if ($newTagShortened === $tagShortened) {
                $prefixIsFree = false;
                break;
            }
        }
        if (!$prefixIsFree) {
            // at this point, we have a duplicated namespace(-predicate)
            $taxonomy = $this->getTaxonomyForTag($newTagName);
            if (!empty($taxonomy['Taxonomy']['exclusive'])) {
                if (
                    ($newTagName === 'tlp:white' && in_array('tlp:clear', $tagNameList)) ||
                    ($newTagName === 'tlp:clear' && in_array('tlp:white', $tagNameList))
                ) {
                    return true;
                }
                return false; // only one tag of this taxonomy is allowed
            } elseif (!empty($taxonomy['TaxonomyPredicate'][0]['exclusive'])) {
                return false; // only one tag belonging to this predicate is allowed
            }
        }
        return true;
    }

    /**
     * @param array $tagList
     * @return array[]
     */
    public function checkIfTagInconsistencies($tagList)
    {
        if (Configure::read('MISP.disable_taxonomy_consistency_checks')) {
            return [
                'global' => [],
                'local' => []
            ];
        }

        $eventTags = array();
        $localEventTags = array();
        foreach ($tagList as $tag) {
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
            // No exclusivity in non taxonomy tags.
            if ($tagShortened === '') {
                continue;
            }
            if (isset($potentiallyConflictingTaxonomy[$tagShortened])) {
                if (!isset($this->__taxonomyConflicts[$tagShortened])) {
                    $this->__taxonomyConflicts[$tagShortened] = $this->getTaxonomyForTag($tagName);
                }
                $potentiallyConflictingTaxonomy[$tagShortened]['count']++;
            } else {
                $potentiallyConflictingTaxonomy[$tagShortened] = [
                    'count' => 1
                ];
            }
            $potentiallyConflictingTaxonomy[$tagShortened]['tagNames'][] = $tagName;
        }
        if (
            !empty($potentiallyConflictingTaxonomy['tlp']) &&
            count($potentiallyConflictingTaxonomy['tlp']['tagNames']) == 2 &&
            in_array('tlp:white', $potentiallyConflictingTaxonomy['tlp']['tagNames']) &&
            in_array('tlp:clear', $potentiallyConflictingTaxonomy['tlp']['tagNames'])
        ) {
            unset($potentiallyConflictingTaxonomy['tlp']);
        }
        foreach ($potentiallyConflictingTaxonomy as $taxonomyName => $potTaxonomy) {
            if ($potTaxonomy['count'] > 1) {
                $taxonomy = $this->__taxonomyConflicts[$taxonomyName];
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
     * @return array|null Returns null if tag is not in taxonomy format
     */
    public function splitTagToComponents($tag)
    {
        preg_match('/^([^:="]+):([^:="]+)(="([^"]+)")?$/i', $tag, $matches);
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

    private function __craftTaxonomiesTags()
    {
        $taxonomies = $this->find('all', [
            'fields' => ['namespace'],
            'contain' => ['TaxonomyPredicate' => ['TaxonomyEntry']],
        ]);
        $allTaxonomyTags = [];
        foreach ($taxonomies as $taxonomy) {
            $namespace = $taxonomy['Taxonomy']['namespace'];
            foreach ($taxonomy['TaxonomyPredicate'] as $predicate) {
                if (isset($predicate['TaxonomyEntry']) && !empty($predicate['TaxonomyEntry'])) {
                    foreach ($predicate['TaxonomyEntry'] as $entry) {
                        $tag = $namespace . ':' . $predicate['value'] . '="' . $entry['value'] . '"';
                        $allTaxonomyTags[$tag] = true;
                    }
                } else {
                    $tag = $namespace . ':' . $predicate['value'];
                    $allTaxonomyTags[$tag] = true;
                }
            }
        }
        return $allTaxonomyTags;
    }

    /**
     * normalizeCustomTagsToTaxonomyFormat Transform all custom tags into their taxonomy version.
     *
     * @return int The number of converted tag
     */
    public function normalizeCustomTagsToTaxonomyFormat(): array
    {
        $tagConverted = 0;
        $rowUpdated = 0;
        $craftedTags = $this->__craftTaxonomiesTags();
        $allTaxonomyTagsByName = Hash::combine($this->getAllTaxonomyTags(false, false, true, false, true), '{n}.Tag.name', '{n}.Tag.id');
        $tagsToMigrate = array_diff_key($allTaxonomyTagsByName, $craftedTags);
        foreach ($tagsToMigrate as $tagToMigrate_name => $tagToMigrate_id) {
            foreach (array_keys($craftedTags) as $craftedTag) {
                if (strcasecmp($craftedTag, $tagToMigrate_name) == 0) {
                    $result = $this->__updateTagToNormalized(intval($tagToMigrate_id), intval($allTaxonomyTagsByName[$craftedTag]));
                    $tagConverted += 1;
                    $rowUpdated += $result['changed'];
                }
            }
        }
        return [
            'tag_converted' => $tagConverted,
            'row_updated' => $rowUpdated,
        ];
    }

    /**
     * __updateTagToNormalized Change the link of element having $source_id tag attached to them for the $target_id one.
     * Updated:
     * - event_tags
     * - attribute_tags
     * - galaxy_cluster_relation_tags
     *
     * Ignored: As this is defined by users, let them do the migration themselves
     * - tag_collection_tags
     * - template_tags
     * - favorite_tags
     *
     * @param int $source_id
     * @param int $target_id
     * @return array
     * @throws Exception
     */
    private function __updateTagToNormalized($source_id, $target_id): array
    {
        return $this->Tag->mergeTag($source_id, $target_id);
    }

    /**
     * @return array
     */
    public function getHighlightedTaxonomies()
    {
        return $this->find('all', [
            'conditions' => [
                'highlighted' => 1,
            ]
        ]);
    }

    /**
     *
     * @param array $highlightedTaxonomies
     * @param array $tags
     * @return array
     */
    public function getHighlightedTags($highlightedTaxonomies, $tags)
    {
        $highlightedTags = [];
        if (is_array($highlightedTaxonomies) && !empty($highlightedTaxonomies)) {
            foreach ($highlightedTaxonomies as $k => $taxonomy) {
                $highlightedTags[$k] = [
                    'taxonomy' => $taxonomy,
                    'tags' => []
                ];

                foreach ($tags as $tag) {
                    $splits = $this->splitTagToComponents($tag['Tag']['name']);
                    if (!empty($splits) && $splits['namespace'] === $taxonomy['Taxonomy']['namespace']) {
                        $highlightedTags[$k]['tags'][] = $tag;
                    }
                }
            }

            return $highlightedTags;
        }

        return $highlightedTags;
    }
}
