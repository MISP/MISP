<?php
class ContextExport
{
    public $additional_params = [
        'flatten' => 1,
        'includeEventTags' => 1,
        'includeGalaxy' => 1,
        'noSightings' => true,
        'noEventReports' => true,
        'noShadowAttributes' => true,
        'sgReferenceOnly' => true,
        'includeEventCorrelations' => false,
        'fetchFullClusters' => false,
    ];

    private $__eventTags = [];
    /** @var array Tag name => Galaxy */
    private $__eventGalaxies = [];

    private $__aggregatedTags = [];
    private $__aggregatedClusters = [];

    private $__taxonomyFetched = [];

    private $__passedOptions = [];

    public $non_restrictive_export = true;
    public $renderView = 'context_view';

    /** @var AttackExport */
    private $AttackExport;

    /** @var Taxonomy */
    private $Taxonomy;

    /** @var Galaxy */
    private $Galaxy;

    public function header($options = array())
    {
        $this->Taxonomy = ClassRegistry::init('Taxonomy');
        $this->Galaxy = ClassRegistry::init('Galaxy');
        App::uses('AttackExport', 'Export');
        $this->AttackExport = new AttackExport();
        $this->__passedOptions = $options;
        $this->AttackExport->handler([], $options);

        return '';
    }

    public function handler($data, $options = array())
    {
        $this->__aggregate($data, Hash::extract($data, 'EventTag.{n}.Tag'));
        if (!empty($data['Attribute'])) {
            foreach ($data['Attribute'] as $attribute) {
                $this->__aggregate($attribute, Hash::extract($attribute, 'AttributeTag.{n}.Tag'));
            }
        }
        $this->AttackExport->handler($data, $options);
        return '';
    }

    public function footer()
    {
        $attackFinal = $this->AttackExport->footer();
        $this->__aggregateTagsPerTaxonomy();
        $this->__aggregateClustersPerGalaxy();
        $attackData = $attackFinal === '' ? [] : JsonTool::decode($attackFinal);
        if (!empty($attackData) && !empty($this->__passedOptions['filters']['staticHtml'])) {
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

    private function __aggregate(array $entity, array $tags)
    {
        if (!empty($entity['Galaxy'])) {
            foreach ($entity['Galaxy'] as $galaxy) {
                foreach ($galaxy['GalaxyCluster'] as $galaxyCluster) {
                    $this->__eventGalaxies[$galaxyCluster['tag_name']] = $galaxyCluster;
                }
            }
        }
        if (!empty($tags)) {
            foreach ($tags as $tag) {
                if (strpos($tag['name'], 'misp-galaxy:') === 0) {
                    continue;
                }
                $this->__eventTags[$tag['name']] = $tag;
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
            return; // tag is not taxonomy tag
        }
        if (!isset($this->__taxonomyFetched[$splits['namespace']])) {
            $fetchedTaxonomy = $this->Taxonomy->getTaxonomyForTag($tagName, true);
            if (!empty($fetchedTaxonomy)) {
                $fetched = [
                    'Taxonomy' => $fetchedTaxonomy['Taxonomy'],
                    'TaxonomyPredicate' => [],
                ];
                foreach ($fetchedTaxonomy['TaxonomyPredicate'] as $predicate) {
                    $fetched['TaxonomyPredicate'][$predicate['value']] = $predicate;
                    if (!empty($predicate['TaxonomyEntry'])) {
                        $fetched['TaxonomyPredicate'][$predicate['value']]['TaxonomyEntry'] = [];
                        foreach ($predicate['TaxonomyEntry'] as $entry) {
                            $fetched['TaxonomyPredicate'][$predicate['value']]['TaxonomyEntry'][$entry['value']] = $entry;
                        }
                    }
                }
                $this->__taxonomyFetched[$splits['namespace']] = $fetched;
            } else {
                // Do not try to fetch non existing taxonomy again
                $this->__taxonomyFetched[$splits['namespace']] = false;
            }
        }
    }

    private function __aggregateTagsPerTaxonomy()
    {
        ksort($this->__eventTags);
        foreach ($this->__eventTags as $tagname => $tagData) {
            $splits = $this->Taxonomy->splitTagToComponents($tagname);
            if ($splits === null) {
                $this->__aggregatedTags['Custom Tags'][]['Tag'] = $tagData;
                continue;
            }
            $taxonomy = [];
            if (!empty($this->__taxonomyFetched[$splits['namespace']])) {
                $taxonomy = $this->__taxonomyFetched[$splits['namespace']];
            }
            if (!empty($taxonomy['TaxonomyPredicate'][$splits['predicate']])) {
                $predicate = $taxonomy['TaxonomyPredicate'][$splits['predicate']];
                $entry = null;
                if (!empty($splits['value']) && isset($predicate['TaxonomyEntry'][$splits['value']])) {
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
        $galaxyTypes = [];
        foreach ($this->__eventGalaxies as $tagName => $foo) {
            $splits = $this->Taxonomy->splitTagToComponents($tagName);
            $galaxyTypes[$splits['predicate']] = true;
        }

        $fetchedGalaxies = $this->Galaxy->find('all', [
            'recursive' => -1,
            'conditions' => array('Galaxy.type' => array_keys($galaxyTypes)),
        ]);
        $fetchedGalaxies = array_column(array_column($fetchedGalaxies, 'Galaxy'), null, 'type');

        ksort($this->__eventGalaxies);
        foreach ($this->__eventGalaxies as $tagName => $cluster) {
            $splits = $this->Taxonomy->splitTagToComponents($tagName);
            $galaxy = $fetchedGalaxies[$splits['predicate']];
            $this->__aggregatedClusters[$splits['predicate']][] = [
                'Galaxy' => $galaxy,
                'GalaxyCluster' => $cluster,
            ];
        }
    }
}
