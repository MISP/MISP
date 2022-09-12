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

    public function footer()
    {
        $attackFinal = $this->AttackExportTool->footer();
        $this->__aggregateTagsPerTaxonomy();
        $this->__aggregateClustersPerGalaxy();
        $attackData = json_decode($attackFinal, true);
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
     * @param array $entity
     * @param array $tags
     * @return void
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
                    continue;
                }
                $this->eventTags[$tag['name']] = $tag;
                $this->fetchTaxonomyForTag($tag['name']);
            }
        }
    }

    /**
     * @param string $tagname
     * @return void
     */
    private function fetchTaxonomyForTag($tagname)
    {
        $splits = $this->Taxonomy->splitTagToComponents($tagname);
        if ($splits === null) {
            return; // tag is not in taxonomy format
        }
        if (!isset($this->__taxonomyFetched[$splits['namespace']])) {
            $fetchedTaxonomy = $this->Taxonomy->getTaxonomyForTag($tagname, false, true);
            if (!empty($fetchedTaxonomy)) {
                $this->__taxonomyFetched[$splits['namespace']]['Taxonomy'] = $fetchedTaxonomy['Taxonomy'];
                $this->__taxonomyFetched[$splits['namespace']]['TaxonomyPredicate'] = [];
                foreach ($fetchedTaxonomy['TaxonomyPredicate'] as $predicate) {
                    $this->__taxonomyFetched[$splits['namespace']]['TaxonomyPredicate'][$predicate['value']] = $predicate;
                    if (!empty($predicate['TaxonomyEntry'])) {
                        $this->__taxonomyFetched[$splits['namespace']]['TaxonomyPredicate'][$predicate['value']]['TaxonomyEntry'] = [];
                        foreach ($predicate['TaxonomyEntry'] as $entry) {
                            $this->__taxonomyFetched[$splits['namespace']]['TaxonomyPredicate'][$predicate['value']]['TaxonomyEntry'][$entry['value']] = $entry;
                        }
                    }
                }
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
        foreach ($this->eventTags as $tagname => $tagData) {
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
        foreach ($this->eventGalaxies as $tagname => $cluster) {
            $splits = $this->Taxonomy->splitTagToComponents($tagname);
            $galaxy = $this->__galaxyFetched[$splits['predicate']];
            $this->__aggregatedClusters[$splits['predicate']][] = [
                'Galaxy' => $galaxy['Galaxy'],
                'GalaxyCluster' => $cluster,
            ];
        }
    }
}
