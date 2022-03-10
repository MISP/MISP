<?php
class ContextExport
{
    private $__attack_export_tool = null;

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
    private $__eventTags = [];
    private $__eventGalaxies = [];

    private $__aggregatedTags = [];
    private $__aggregatedClusters = [];

    private $__taxonomyFetched = [];
    private $__galaxyFetched = [];

    public $non_restrictive_export = true;
    public $renderView = 'context_view';

    public function handler($data, $options = array())
    {
        $this->__aggregate($data, Hash::extract($data, 'EventTag.{n}.Tag'));
        if (!empty($data['Attribute'])) {
            foreach ($data['Attribute'] as $attribute) {
                $this->__aggregate($attribute, Hash::extract($attribute, 'AttributeTag.{n}.Tag'));
            }
        }

        $this->__attack_export_tool->handler($data, $options);
        return '';
    }

    public function header($options = array())
    {
        $this->__TaxonomyModel = ClassRegistry::init('Taxonomy');
        $this->__GalaxyModel = ClassRegistry::init('Galaxy');
        App::uses('AttackExport', 'Export');
        $this->__attack_export_tool = new AttackExport();
        $this->__attack_export_tool->handler($options);

        return '';
    }

    public function footer()
    {
        $attackFinal = $this->__attack_export_tool->footer();
        $this->__aggregateTagsPerTaxonomy();
        $this->__aggregateClustersPerGalaxy();
        $attackData = json_decode($attackFinal, true);
        return json_encode([
            'attackData' => $attackData,
            'tags' => $this->__aggregatedTags,
            'clusters' => $this->__aggregatedClusters,
        ]);
    }

    public function separator()
    {
        $this->__attack_export_tool->separator();
        return '';
    }

    private function __aggregate($entity, $tags)
    {
        if (!empty($entity['Galaxy'])) {
            foreach ($entity['Galaxy'] as $galaxy) {
                foreach ($galaxy['GalaxyCluster'] as $galaxyCluster) {
                    $this->__eventGalaxies[$galaxyCluster['tag_name']] = $galaxyCluster;
                    $this->fetchGalaxyForTag($galaxyCluster['tag_name']);
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

    private function fetchTaxonomyForTag($tagname)
    {
        $splits = $this->__TaxonomyModel->splitTagToComponents($tagname);
        if (!isset($this->__taxonomyFetched[$splits['namespace']])) {
            $fetchedTaxonomy = $this->__TaxonomyModel->getTaxonomyForTag($tagname, false, true);
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

    private function fetchGalaxyForTag($tagname)
    {
        $splits = $this->__TaxonomyModel->splitTagToComponents($tagname);
        $galaxy = $this->__GalaxyModel->find('first', array(
            'recursive' => -1,
            'conditions' => array('Galaxy.type' => $splits['predicate'])
        ));
        $this->__galaxyFetched[$splits['predicate']] = $galaxy;
    }

    private function __aggregateTagsPerTaxonomy()
    {
        ksort($this->__eventTags);
        foreach ($this->__eventTags as $tagname => $tagData) {
            $splits = $this->__TaxonomyModel->splitTagToComponents($tagname);
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
        ksort($this->__eventGalaxies);
        foreach ($this->__eventGalaxies as $tagname => $cluster) {
            $splits = $this->__TaxonomyModel->splitTagToComponents($tagname);
            $galaxy = $this->__galaxyFetched[$splits['predicate']];
            $this->__aggregatedClusters[$splits['predicate']][] = [
                'Galaxy' => $galaxy['Galaxy'],
                'GalaxyCluster' => $cluster,
            ];
        }
    }
}
