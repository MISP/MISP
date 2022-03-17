<div>
    <h1><?= __('Aggregated context data') ?></h1>
    <h2><?= __('Tags and Taxonomies') ?></h2>
    <div>
        <?php
        $htmlTags = '';
        foreach ($tags as $namespace => $entries) {
            $htmlTags .= sprintf('<div><h4>%s</h4></div>', h($namespace));
            if (!empty($entries[0]['Taxonomy']['description'])) {
                $htmlTags .= sprintf('<div><i>%s</i></div>', h($entries[0]['Taxonomy']['description']));
            }
            $htmlTags .= '<ul>';
            foreach ($entries as $entry) {
                $taxonomyInfo = '<ul>';
                if (!empty($entry['TaxonomyPredicate'])) {
                    $taxonomyInfo .= sprintf(
                        '<li><strong>%s</strong>: %s</li>',
                        h($entry['TaxonomyPredicate']['value']),
                        h($entry['TaxonomyPredicate']['expanded'])
                    );
                }
                if (!empty($entry['TaxonomyEntry'])) {
                    $taxonomyInfo .= sprintf(
                        '<li><strong>%s</strong>: %s</li>',
                        h($entry['TaxonomyEntry']['value']),
                        h($entry['TaxonomyEntry']['expanded'])
                    );
                }
                $taxonomyInfo .= '</ul>';
                $htmlTags .= sprintf(
                    '<li>%s</li>%s',
                    $this->element('tag', ['tag' => $entry]),
                    $taxonomyInfo
                );
            }
            $htmlTags .= '</ul>';
        }
        echo $htmlTags;
        ?>
    </div>

    <h2><?= __('Galaxy Clusters') ?></h2>
    <div>
        <?php
        $htmlClusters = '';
        foreach ($clusters as $tagname => $entries) {
            $htmlClusters .= sprintf(
                '<div><h4>%s %s</h4></div>',
                sprintf('<i class="%s"></i>', $this->FontAwesome->getClass($entries[0]['Galaxy']['icon'])),
                h($entries[0]['Galaxy']['name'])
            );
            if (!empty($entries[0]['Galaxy']['description'])) {
                $htmlClusters .= sprintf('<div><i>%s</i></div>', h($entries[0]['Galaxy']['description']));
            }
            $htmlClusters .= '<ul>';
            foreach ($entries as $cluster) {
                $htmlClusters .= sprintf(
                    '<li><strong><a href="%s" target="_blank">%s</a></strong></li> %s',
                    $baseurl . '/galaxy_clusters/view/' . h($cluster['GalaxyCluster']['id']),
                    h($cluster['GalaxyCluster']['value']),
                    strlen(h($cluster['GalaxyCluster']['description'])) > 300 ?
                        (substr(h($cluster['GalaxyCluster']['description']), 0, 300) . '...') : h($cluster['GalaxyCluster']['description'])
                );
            }
            $htmlClusters .= '</ul>';
        }
        echo $htmlClusters;
        ?>
    </div>

    <h2><?= __('Mitre ATT&CK Matrix') ?></h2>
    <div id="attackmatrix_div" style="position: relative; border: solid 1px;" class="statistics_attack_matrix">
        <?= $this->element('view_galaxy_matrix', $attackData); ?>
    </div>
</div>
