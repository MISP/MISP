<?php
    echo '<div class="index">';
    echo $this->element('/genericElements/IndexTable/index_table', array(
        'data' => array(
            'data' => $data,
            'primary_id_path' => 'Feed.id',
            'top_bar' => array(
                'children' => array(
                    array(
                        'children' => array(
                            array(
                                'class' => 'hidden mass-select',
                                'text' => __('Enable selected'),
                                'onClick' => "multiSelectToggleFeeds",
                                'onClickParams' => array('1', '0')
                            ),
                            array(
                                'class' => 'hidden mass-select',
                                'text' => __('Disable selected'),
                                'onClick' => "multiSelectToggleFeeds",
                                'onClickParams' => array('0', '0')
                            ),
                            array(
                                'class' => 'hidden mass-select',
                                'text' => __('Enable caching for selected'),
                                'onClick' => "multiSelectToggleFeeds",
                                'onClickParams' => array('1', '1')
                            ),
                            array(
                                'class' => 'hidden mass-select',
                                'text' => __('Disable caching for selected'),
                                'onClick' => "multiSelectToggleFeeds",
                                'onClickParams' => array('0', '1')
                            )
                        )
                    ),
                    array(
                        'children' => array(
                            array(
                                'url' => $baseurl . '/feeds/index/scope:default',
                                'text' => __('Default feeds'),
                                'active' => $scope === 'default',
                                'style' => 'display:inline;'
                            ),
                            array(
                                'url' => $baseurl . '/feeds/index/scope:custom',
                                'text' => __('Custom feeds'),
                                'active' => $scope === 'custom',
                                'style' => 'display:inline;'
                            ),
                            array(
                                'url' => $baseurl . '/feeds/index/scope:all',
                                'text' => __('All feeds'),
                                'active' => $scope === 'all',
                                'style' => 'display:inline;'
                            ),
                            array(
                                'url' => $baseurl . '/feeds/index/scope:enabled',
                                'text' => __('Enabled feeds'),
                                'active' => $scope === 'enabled',
                                'style' => 'display:inline;'
                            )
                        )
                    ),
                    array(
                        'type' => 'search',
                        'button' => __('Filter'),
                        'placeholder' => __('Enter value to search'),
                        'data' => '',
                        'searchKey' => 'quickFilter'
                    )
                )
            ),
            'fields' => array(
                array(
                    'element' => 'selector',
                    'class' => 'short',
                    'data' => array(
                        'id' => array(
                            'value_path' => 'Feed.id'
                        )
                    )
                ),
                array(
                    'name' => __('ID'),
                    'sort' => 'Feed.id',
                    'class' => 'short',
                    'data_path' => 'Feed.id',
                ),
                array(
                    'name' => __('Enabled'),
                    'sort' => 'Feed.enabled',
                    'title' => __('Enable pulling the feed into your MISP as events/attributes.'),
                    'class' => 'short',
                    'element' => 'boolean',
                    'data_path' => 'Feed.enabled',
                    'rule_path' => 'Feed.rules'
                ),
                array(
                    'name' => __('Caching'),
                    'sort' => 'Feed.caching_enabled',
                    'title' => __('Enable caching the feed into Redis - allowing for correlations to the feed to be shown.'),
                    'class' => 'short',
                    'element' => 'boolean',
                    'data_path' => 'Feed.caching_enabled',
                ),
                array(
                    'name' => __('Name'),
                    'class' => 'shortish',
                    'data_path' => 'Feed.name',
                    'sort' => 'Feed.name',
                ),
                array(
                    'name' => __('Format'),
                    'class' => 'short',
                    'sort' => 'Feed.source_format',
                    'data_path' => 'Feed.source_format'
                ),
                array(
                    'name' => __('Provider'),
                    'class' => 'short',
                    'data_path' => 'Feed.provider',
                    'sort' => 'Feed.provider'
                ),
                array(
                    'name' => __('Org'),
                    'class' => 'short',
                    'data_path' => 'Orgc',
                    'sort' => 'Feed.Orgc',
                    'element' => 'org'
                ),
                array(
                    'name' => __('Source'),
                    'class' => 'short',
                    'data_path' => 'Feed.input_source',
                    'sort' => 'Feed.input_source'
                ),
                array(
                    'name' => __('URL'),
                    'class' => 'shortish',
                    'data_path' => 'Feed.url',
                    'sort' => 'Feed.url'
                ),
                array(
                    'name' => __('Headers'),
                    'class' => 'shortish',
                    'data_path' => 'Feed.headers',
                    'requirement' => $isSiteAdmin
                ),
                array(
                    'name' => __('Target'),
                    'class' => 'short',
                    'data_path' => array(
                        'Feed.fixed_event',
                        'Feed.source_format',
                        'Feed.event_error',
                        'Feed.event_id',
                        'Feed.enabled'
                    ),
                    'element' => 'target_event'
                ),
                array(
                    'name' => __('Publish'),
                    'class' => 'short',
                    'element' => 'boolean',
                    'sort' => 'Feed.publish',
                    'data_path' => 'Feed.publish'
                ),
                array(
                    'name' => __('Delta'),
                    'title' => __('Delta Merge strategy - align the local feed with the remote state'),
                    'class' => 'short',
                    'element' => 'boolean',
                    'sort' => 'Feed.delta_merge',
                    'data_path' => 'Feed.delta_merge'
                ),
                array(
                    'name' => __('Override'),
                    'title' => __('Override the IDS flags and set all derived attribute to IDS off'),
                    'class' => 'short',
                    'element' => 'boolean',
                    'sort' => 'Feed.ids',
                    'data_path' => 'Feed.ids'
                ),
                array(
                    'name' => __('Distribution'),
                    'class' => 'short',
                    'data_path' => 'Feed.distribution',
                    'element' => 'distribution_levels'
                ),
                array(
                    'name' => __('Tag'),
                    'class' => 'short',
                    'data_path' => 'Tag',
                    'element' => 'tags',
                    'scope' => 'feeds',
                    'includeTagCollection' => true,
                ),
                array(
                    'name' => __('Visible'),
                    'class' => 'short',
                    'data_path' => 'Feed.lookup_visible',
                    'element' => 'boolean',
                    'sort' => 'Feed.lookup_visible'
                ),
                array(
                    'name' => __('Caching'),
                    'class' => 'short',
                    'data_path' => 'Feed.cache_timestamp',
                    'enabled_path' => 'Feed.caching_enabled',
                    'element' => 'caching',
                    'sort' => 'Feed.cache_timestamp',
                    'requirement' => $isSiteAdmin,
                )
            ),
            'title' => __('Feeds'),
            'description' => __('Generate feed lookup caches or fetch feed data (enabled feeds only)'),
            'html' => $isSiteAdmin ? sprintf(
                '<div class="toggleButtons">%s%s%s%s%s</div><br>',
                $this->Form->postButton(
                    __('Load default feed metadata'),
                    array('controller' => 'feeds', 'action' => 'loadDefaultFeeds'),
                    array(
                        'class' => 'qet btn btn-inverse',
                        'div' => false,
                        'style' => 'margin-right:20px;'
                    )
                ),
                sprintf(
                    '<a href="%s/feeds/cacheFeeds/all" class="%s">%s</a>',
                    $baseurl,
                    'toggle-left qet btn btn-inverse',
                    __('Cache all feeds')
                ),
                sprintf(
                    '<a href="%s/feeds/cacheFeeds/freetext" class="%s">%s</a>',
                    $baseurl,
                    'toggle qet btn btn-inverse',
                    __('Cache freetext/CSV feeds')
                ),
                sprintf(
                    '<a href="%s/feeds/cacheFeeds/misp" class="%s">%s</a>',
                    $baseurl,
                    'toggle-right qet btn btn-inverse',
                    __('Cache MISP feeds')
                ),
                sprintf(
                    '<a href="%s/feeds/fetchFromAllFeeds" class="%s" style="%s">%s</a>',
                    $baseurl,
                    'btn btn-primary qet',
                    'margin-left:20px;',
                    __('Fetch and store all feed data')
                )
            ) : '',
            'actions' => array(
                array(
                    'url' => $baseurl . '/feeds/previewIndex',
                    'url_params_data_paths' => 'Feed.id',
                    'icon' => 'search',
                    'title' => __('Explore the events remotely')
                ),
                array(
                    'url' => $baseurl . '/feeds/fetchFromFeed',
                    'url_params_data_paths' => 'Feed.id',
                    'icon' => 'arrow-circle-down',
                    'title' => __('Fetch all events'),
                    'requirement' => $isSiteAdmin,
                    'complex_requirement' => array(
                        'options' => array(
                            'datapath' => array(
                                'event_error' => 'Feed.event_error',
                                'enabled' => 'Feed.enabled'
                            ),
                        ),
                        'function' => function($row, $options) {
                            if (!empty($options['datapath']['event_error'])) {
                                return false;
                            }
                            if (empty($options['datapath']['enabled'])) {
                                return false;
                            }
                            return true;
                        }
                    )
                ),
                array(
                    'url' => $baseurl . '/feeds/edit',
                    'url_params_data_paths' => 'Feed.id',
                    'icon' => 'edit',
                    'title' => __('Edit'),
                    'requirement' => $isSiteAdmin
                ),
                array(
                    'url' => $baseurl . '/feeds/delete',
                    'url_params_data_paths' => 'Feed.id',
                    'icon' => 'trash',
                    'title' => __('Delete'),
                    'postLink' => 1,
                    'postLinkConfirm' => __('Are you sure you want to permanently remove the feed?'),
                    'requirement' => $isSiteAdmin
                ),
                array(
                    'url' => $baseurl . '/feeds/view',
                    'url_params_data_paths' => 'Feed.id',
                    'url_extension' => 'json',
                    'icon' => 'cloud-download-alt',
                    'title' => __('Download feed metadata as JSON')
                ),
            )
        )
    ));
    echo '</div>';
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'feeds', 'menuItem' => 'index'));
?>
<script type="text/javascript">
    $(function() {
        popoverStartup();
        $('.select').on('change', function() {
            listCheckboxesChecked();
        });
        $('#quickFilterButton').click(function() {
            runIndexQuickFilter();
        });
    });
</script>
