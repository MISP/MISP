<?php
class ContextExport
{
    /** @var AttackExport */
    private $AttackExportTool;

    public $additional_params = [
        'flatten' => 1,
        'includeEventTags' => 1,
        'includeGalaxy' => 1,
        'noSightings' => true,
        'noEventReports' => true,
        'noShadowAttributes' => true,
        'sgReferenceOnly' => true,
        'includeEventCorrelations' => false,
    ];
    private $eventTags = [];
    private $eventGalaxies = [];

    private $__aggregatedTags = [];
    private $__aggregatedClusters = [];

    private $__taxonomyFetched = [];
    private $__galaxyFetched = [];

    private $__passedOptions = [];

    public $non_restrictive_export = true;
    public $renderView = 'context_view';

    /** @var Taxonomy */
    private $Taxonomy;

    /** @var Galaxy */
    private $GalaxyModel;

    public function header($options = array())
    {
        $this->Taxonomy = ClassRegistry::init('Taxonomy');
        $this->GalaxyModel = ClassRegistry::init('Galaxy');
        App::uses('AttackExport', 'Export');
        $this->AttackExportTool = new AttackExport();
        $this->AttackExportTool->handler($options);
        $this->__passedOptions = $options;

        return '';
    }

    /**
     * @var array $data Event data
     * @throws RedisException
     */
    public function handler($data, $options = array())
    {
        $this->__aggregate($data, Hash::extract($data, 'EventTag.{n}.Tag'));
        if (!empty($data['Attribute'])) {
            foreach ($data['Attribute'] as $attribute) {
                $this->__aggregate($attribute, Hash::extract($attribute, 'AttributeTag.{n}.Tag'));
            }
        }
        $this->AttackExportTool->handler($data, $options);
        return '';
    }

    public function footer()
    {
        $attackFinal = $this->AttackExportTool->footer();
        $this->__aggregateTagsPerTaxonomy();
        $this->__aggregateClustersPerGalaxy();
        $attackData = JsonTool::decode($attackFinal);
        if (!empty($this->__passedOptions['filters']['staticHtml'])) {
            $attackData['static'] = true;
        }
        return JsonTool::encode([
            'attackData' => $attackData,
            'tags' => $this->__aggregatedTags,
            'clusters' => $this->__aggregatedClusters,
        ]);
    }

    public function separator()
    {
        return '';
    }

    /**
     * @param array $entity Event or attribute array
     * @param array $tags Event and attribute tags
     * @return void
     * @throws RedisException
     */
    private function __aggregate($entity, $tags)
    {
        if (!empty($entity['Galaxy'])) {
            foreach ($entity['Galaxy'] as $galaxy) {
                foreach ($galaxy['GalaxyCluster'] as $galaxyCluster) {
                    $this->eventGalaxies[$galaxyCluster['tag_name']] = $galaxyCluster;
                    $this->fetchGalaxyForTag($galaxyCluster['tag_name']);
                }
            }
        }
        if (!empty($tags)) {
            foreach ($tags as $tag) {
                if (strpos($tag['name'], 'misp-galaxy:') === 0) {
                    continue; // skip if tag is galaxy
                }
                $this->eventTags[$tag['name']] = $tag;
                $this->fetchTaxonomyForTag($tag['name']);
            }
        }
    }

    /**
     * @param string $tagName
     * @return void
     * @throws RedisException
     */
    private function fetchTaxonomyForTag($tagName)
    {
        $splits = $this->Taxonomy->splitTagToComponents($tagName);
        if ($splits === null) {
            return; // skip if tag is not in taxonomy format
        }
        if (!isset($this->__taxonomyFetched[$splits['namespace']])) {
            $fetchedTaxonomy = $this->Taxonomy->getTaxonomyForTag($tagName, false, true);
            if (!empty($fetchedTaxonomy)) {
                $output = [
                    'Taxonomy' => $fetchedTaxonomy['Taxonomy'],
                    'TaxonomyPredicate' => [],
                ];
                foreach ($fetchedTaxonomy['TaxonomyPredicate'] as $predicate) {
                    $output['TaxonomyPredicate'][$predicate['value']] = $predicate;
                    if (!empty($predicate['TaxonomyEntry'])) {
                        $output['TaxonomyPredicate'][$predicate['value']]['TaxonomyEntry'] = [];
                        foreach ($predicate['TaxonomyEntry'] as $entry) {
                            $output['TaxonomyPredicate'][$predicate['value']]['TaxonomyEntry'][$entry['value']] = $entry;
                        }
                    }
                }
                $this->__taxonomyFetched[$splits['namespace']] = $output;
            } else {
                $this->__taxonomyFetched[$splits['namespace']] = false;
            }
        }
    }

    /**
     * @param string $tagname
     * @return void
     */
    private function fetchGalaxyForTag($tagname)
    {
        $splits = $this->Taxonomy->splitTagToComponents($tagname);
        if ($splits === null) {
            return; // tag is not in taxonomy format
        }
        if (isset($this->__galaxyFetched[$splits['predicate']])) {
            return; // already fetched
        }
        $galaxy = $this->GalaxyModel->find('first', array(
            'recursive' => -1,
            'conditions' => array('Galaxy.type' => $splits['predicate'])
        ));
        $this->__galaxyFetched[$splits['predicate']] = $galaxy;
    }

    private function __aggregateTagsPerTaxonomy()
    {
        ksort($this->eventTags);
        foreach ($this->eventTags as $tagName => $tagData) {
            $splits = $this->Taxonomy->splitTagToComponents($tagName);
            if ($splits === null) {
                $this->__aggregatedTags['Custom Tags'][]['Tag'] = $tagData;
                continue;
            }
            $taxonomy = $this->__taxonomyFetched[$splits['namespace']] ?? false;
            if ($taxonomy && !empty($taxonomy['TaxonomyPredicate'][$splits['predicate']])) {
                $predicate = $taxonomy['TaxonomyPredicate'][$splits['predicate']];
                $entry = null;
                if (!empty($splits['value'])) {
                    $entry = $predicate['TaxonomyEntry'][$splits['value']];
                }
                unset($predicate['TaxonomyEntry']);
                $this->__aggregatedTags[$splits['namespace']][] = [
                    'Taxonomy' => $taxonomy['Taxonomy'],
                    'TaxonomyPredicate' => $predicate,
                    'TaxonomyEntry' => $entry,
                    'Tag' => $tagData,
                ];
            } else {
                $this->__aggregatedTags['Custom Tags'][]['Tag'] = $tagData;
            }
        }
    }

    private function __aggregateClustersPerGalaxy()
    {
        ksort($this->eventGalaxies);
        foreach ($this->eventGalaxies as $tagName => $cluster) {
            $splits = $this->Taxonomy->splitTagToComponents($tagName);
            $galaxy = $this->__galaxyFetched[$splits['predicate']];
            $this->__aggregatedClusters[$splits['predicate']][] = [
                'Galaxy' => $galaxy['Galaxy'],
                'GalaxyCluster' => $cluster,
            ];
        }
    }
}
