<?php
    $html_description = '';
    $noticeTitle = '<p>' . __('This information is purely informational and is typically part of the normal operation of the system.') . '</p>';
    if ($isSiteAdmin) {
        $notices = [];
        $severity = '';
        $hasUnkwownCustomClusters = $unkownClustersDetails['unknownCustomClusters'] > 0;
        $hasUnkwownDefaultClusters = $unkownClustersDetails['unknownDefaultClusters'] > 0;
        if ($hasUnkwownCustomClusters) {
            $severity = 'info';
            $content = sprintf(' %s', __('Your instance has detected <b style="font-size: larger;">%s</b> <b>custom cluster(s)</b> that it doesn\'t recognize. This may indicate one of two things: either these clusters haven\'t been properly synchronized, or you weren\'t authorized to view them during the synchronization process. In most cases, you can safely ignore this message. However, if you believe you should have access to these clusters, please check your synchronization settings and ask the instances sending data to you to review theirs as well. Sample(s):', $unkownClustersDetails['unknownCustomClusters']));
            $tagSampleHTML = sprintf('<li>%s</li>', implode('</li><li>', $unkownClustersDetails['unknownCustomClustersSamples']));
            $content .= $tagSampleHTML;
            $notices[] = sprintf('<div class="alert alert-%s" style="max-width: 960px; margin-bottom: 0.25em;"><b style="font-size: larger;">%s:</b>%s</div>', $severity, __('Info'), $content);
        }
        if ($hasUnkwownDefaultClusters) {
            $severity = 'info';
            $content = sprintf(' %s', __('Your instance has detected <b style="font-size: larger;">%s</b> <b>default cluster(s)</b> that it doesn\'t recognize, which may mean your galaxies are outdated. To fix this, update to the latest version from the misp-galaxy repository and load the JSON files into your database by clicking the "Update Galaxies" button. Sample(s):', $unkownClustersDetails['unknownDefaultClusters']));
            $tagSampleHTML = sprintf('<li>%s</li>', implode('</li><li>', $unkownClustersDetails['unknownDefaultClustersSamples']));
            $content .= $tagSampleHTML;
            $notices[] = sprintf('<div class="alert alert-%s" style="max-width: 960px; margin-bottom: 0.25em;"><b style="font-size: larger;">%s:</b>%s</div>', $severity, __('Info'), $content);
        }
        if (!empty($notices)) {
            array_unshift($notices, $noticeTitle);
            $html_description = implode('', $notices);
            $bootstrapAccordionBlueprint = '<div class="accordion" id="accordionClusterInfo" style="margin-bottom: 0.5em;">
                <div class="accordion-group"><div class="accordion-heading"><a class="accordion-toggle" data-toggle="collapse" data-parent="#accordionClusterInfo" href="#collapseOne"><i class="fas fa-caret-down"></i> %s</a></div>
                <div id="collapseOne" class="accordion-body collapse"><div class="accordion-inner">%s</div></div></div>
            </div>';
            $html_description = sprintf($bootstrapAccordionBlueprint, __('Show information about your clusters'), $html_description);
        }
    }
?>

<?php
    echo '<div class="index">';
    echo $this->element('/genericElements/IndexTable/index_table', array(
        'data' => array(
            'data' => $galaxyList,
            'top_bar' => array(
                'children' => array(
                    array(
                        'type' => 'simple',
                        'children' => array(
                            array(
                                'url' => $baseurl . '/galaxies/index',
                                'text' => __('All'),
                                'active' => !isset($passedArgsArray['enabled']),
                            ),
                            array(
                                'url' => $baseurl . '/galaxies/index/enabled:1',
                                'text' => __('Enabled'),
                                'active' => isset($passedArgsArray['enabled']) && $passedArgsArray['enabled'] === "1",
                            ),
                            array(
                                'url' => $baseurl . '/galaxies/index/enabled:0',
                                'text' => __('Disabled'),
                                'active' => isset($passedArgsArray['enabled']) && $passedArgsArray['enabled'] === "0",
                            )
                        )
                    ),
                    array(
                        'type' => 'search',
                        'button' => __('Filter'),
                        'placeholder' => __('Enter value to search'),
                        'searchKey' => 'value',
                        'cancel' => array(
                            'fa-icon' => 'times',
                            'title' => __('Remove filters'),
                            'onClick' => 'cancelSearch',
                        )
                    )
                )
            ),
            'fields' => array(
                array(
                    'name' => __('ID'),
                    'sort' => 'Galaxy.id',
                    'element' => 'links',
                    'class' => 'short',
                    'data_path' => 'Galaxy.id',
                    'url' => $baseurl . '/galaxies/view/%s'
                ),
                array(
                    'name' => __('Icon'),
                    'element' => 'icon',
                    'class' => 'short',
                    'data_path' => 'Galaxy.icon',
                ),
                array(
                    'name' => __('Name'),
                    'sort' => 'name',
                    'class' => 'short',
                    'data_path' => 'Galaxy.name',
                ),
                array(
                    'name' => __('Version'),
                    'class' => 'short',
                    'data_path' => 'Galaxy.version',
                ),
                array(
                    'name' => __('Namespace'),
                    'class' => 'short',
                    'sort' => 'Galaxy.namespace',
                    'data_path' => 'Galaxy.namespace',
                ),
                array(
                    'name' => __('Description'),
                    'data_path' => 'Galaxy.description',
                ),
                array(
                    'name' => __('Enabled'),
                    'element' => 'boolean',
                    'sort' => 'enabled',
                    'class' => 'short',
                    'data_path' => 'Galaxy.enabled',
                ),
                array(
                    'name' => __('Local Only'),
                    'element' => 'boolean',
                    'sort' => 'local_only',
                    'class' => 'short',
                    'data_path' => 'Galaxy.local_only',
                ),
            ),
            'title' => __('Galaxy index'),
            'html' => $html_description,
            'actions' => array(
                array(
                    'url' => '/galaxies/view',
		            'title' => __('View'),
                    'url_params_data_paths' => array(
                        'Galaxy.id'
                    ),
                    'icon' => 'eye',
                    'dbclickAction' => true
                ),
                array(
                    'title' => __('Enable'),
                    'icon' => 'play',
                    'postLink' => true,
                    'url' => $baseurl . '/galaxies/enable',
                    'url_params_data_paths' => ['Galaxy.id'],
                    'postLinkConfirm' => __('Are you sure you want to enable this galaxy library?'),
                    'complex_requirement' => function ($row) use ($isSiteAdmin) {
                        return $isSiteAdmin && !$row['Galaxy']['enabled'];
                    }
                ),
                array(
                    'title' => __('Disable'),
                    'icon' => 'stop',
                    'postLink' => true,
                    'url' => $baseurl . '/galaxies/disable',
                    'url_params_data_paths' => ['Galaxy.id'],
                    'postLinkConfirm' => __('Are you sure you want to disable this galaxy library?'),
                    'complex_requirement' => function ($row) use ($isSiteAdmin) {
                        return $isSiteAdmin && $row['Galaxy']['enabled'];
                    }
                ),
                [
                    'title' => __('Edit'),
                    'icon' => 'edit',
                    'title' => __('View'),
                    'url' => $baseurl . '/galaxies/edit',
                    'url_params_data_paths' => ['Galaxy.id'],
                    'complex_requirement' => function ($row) use ($isSiteAdmin, $me) {
                        return !$row['Galaxy']['default'] && ($isSiteAdmin || ($row['Galaxy']['org_id'] === $me['org_id'] && $me['Role']['perm_galaxy_editor']));
                    }
                ],
                array(
                    'url' => '/galaxies/delete',
                    'title' => __('Delete'),
                    'url_params_data_paths' => array(
                        'Galaxy.id'
                    ),
                    'postLink' => true,
                    'postLinkConfirm' => __('Are you sure you want to delete the Galaxy?'),
                    'icon' => 'trash',
                    'requirement' => $isSiteAdmin,
                ),
            )
        )
    ));
    echo '</div>';
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'galaxies', 'menuItem' => 'galaxy_index'));
?>
<script>
    $(function() {
        $('#quickFilterButton').click(function() {
            runIndexQuickFilter();
        });
    });
</script>
