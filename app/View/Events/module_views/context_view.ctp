<div>
    <?php if (!empty($tags)): ?>
        <h2><?= __('Tags and Taxonomies') ?></h2>
        <div>
            <?php
            $htmlTags = '';
            $customTagHtml = '';
            foreach ($tags as $namespace => $entries) {
                if (empty($entries[0]['Taxonomy'])) {
                    continue;
                }
                $htmlTags .= sprintf('<div><h4><code>%s</code></h4></div>', h($namespace));
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
    <?php endif; ?>

    <?php if (!empty($clusters)): ?>
        <h2><?= __('Galaxy Clusters') ?></h2>
        <div>
            <?php
            foreach ($clusters as $tagname => $entries) {
                echo sprintf(
                    '<div><h4>%s %s</h4></div>',
                    sprintf('<i class="%s"></i>', $this->FontAwesome->getClass($entries[0]['Galaxy']['icon'])),
                    h($entries[0]['Galaxy']['name'])
                );
                if (!empty($entries[0]['Galaxy']['description'])) {
                    echo sprintf('<div><i>%s</i></div>', h($entries[0]['Galaxy']['description']));
                }
                echo '<ul>';
                foreach ($entries as $cluster) {
                    $description = $this->Markdown->toText($cluster['GalaxyCluster']['description']);
                    echo sprintf(
                        '<li><strong><a href="%s" target="_blank">%s</a></strong></li> %s',
                        $baseurl . '/galaxy_clusters/view/' . h($cluster['GalaxyCluster']['id']),
                        h($cluster['GalaxyCluster']['value']),
                        strlen($description) > 300 ?
                            (h(mb_substr($description, 0, 300)) . '...') : h($description)
                    );
                }
                echo '</ul>';
            }
            ?>
        </div>
    <?php endif; ?>

    <?php if (!empty($attackData)): ?>
        <h2><?= __('Mitre ATT&CK Matrix') ?></h2>
        <div style="position: relative;" class="statistics_attack_matrix">
            <?= $this->element('view_galaxy_matrix', $attackData); ?>
        </div>
    <?php endif; ?>
</div>
