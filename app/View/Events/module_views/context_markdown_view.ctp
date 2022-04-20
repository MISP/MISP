<?php
    $md = [];
    $md[] = sprintf('# %s', __('Aggregated context data'));

    $md[] = sprintf('## %s', __('Tags and Taxonomies'));
    $mdTags = [];
    foreach ($tags as $namespace => $entries) {
        $mdTags[] = sprintf('#### %s', h($namespace));
        if (!empty($entries[0]['Taxonomy']['description'])) {
        $mdTags[] = sprintf('*%s*', h($entries[0]['Taxonomy']['description']));
        }
        foreach ($entries as $entry) {
            $taxonomyInfo = [];
            if (!empty($entry['TaxonomyPredicate'])) {
                $taxonomyInfo[] = sprintf(
                    '    - **%s**: %s',
                    h($entry['TaxonomyPredicate']['value']),
                    h($entry['TaxonomyPredicate']['expanded'])
                );
            }
            if (!empty($entry['TaxonomyEntry'])) {
                $taxonomyInfo[] = sprintf(
                    '    - **%s**: %s',
                    h($entry['TaxonomyEntry']['value']),
                    h($entry['TaxonomyEntry']['expanded'])
                );
            }
            $mdTags[] = sprintf(
                '- %s' . PHP_EOL . '%s',
                $this->element('tag', ['tag' => $entry]),
                implode(PHP_EOL, $taxonomyInfo)
            );
        }
    }
    $md[] = implode(PHP_EOL, $mdTags);

    $md[] = sprintf('## %s', __('Galaxy Clusters'));
    $mdClusters = [];
    foreach ($clusters as $tagname => $entries) {
        $mdClusters[] = sprintf(
            '#### %s %s',
            sprintf('<i class="%s"></i>', $this->FontAwesome->getClass($entries[0]['Galaxy']['icon'])),
            h($entries[0]['Galaxy']['name'])
        );
        if (!empty($entries[0]['Galaxy']['description'])) {
            $mdClusters[] = sprintf('*%s*', h($entries[0]['Galaxy']['description']));
        }
        foreach ($entries as $cluster) {
            $mdClusters[] = sprintf(
                '- *[%s](%s)*' . PHP_EOL . '%s',
                h($cluster['GalaxyCluster']['value']),
                $baseurl . '/galaxy_clusters/view/' . h($cluster['GalaxyCluster']['id']),
                strlen(h($cluster['GalaxyCluster']['description'])) > 300 ?
                    (substr(h($cluster['GalaxyCluster']['description']), 0, 300) . '...') : h($cluster['GalaxyCluster']['description'])
            );
        }
    }
    $md[] = implode(PHP_EOL, $mdClusters);

    // $md[] = sprintf('## %s', __('Mitre ATT&CK Matrix'));
    // $md[] = $this->element('view_galaxy_matrix', $attackData);

    echo implode(PHP_EOL, $md);
