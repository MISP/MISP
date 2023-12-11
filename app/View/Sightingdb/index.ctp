<?php
    echo '<div class="index">';
    echo $this->element('/genericElements/IndexTable/index_table', array(
        'data' => array(
            'data' => $data,
            'top_bar' => array(
                'children' => array(
                    array(
                        'type' => 'search',
                        'button' => __('Filter'),
                        'placeholder' => __('Enter value to search'),
                        'data' => '',
                        'searchKey' => 'value'
                    )
                )
            ),
            'fields' => array(
                array(
                    'name' => __('Enabled'),
                    'sort' => 'Sightingdb.enabled',
                    'element' => 'boolean',
                    'class' => 'short',
                    'data_path' => 'Sightingdb.enabled'
                ),
                array(
                    'name' => __('Id'),
                    'sort' => 'id',
                    'class' => 'short',
                    'data_path' => 'Sightingdb.id'
                ),
                array(
                    'name' => __('Test'),
                    'class' => 'short',
                    'element' => 'tester',
                    'button' => __('Run'),
                    'button_class' => 'btn-mini btn-inverse',
                    'url' => '/sightingdb/requestStatus/',
                    'data_path' => 'Sightingdb.id'
                ),
                array(
                    'name' => __('Quick Search'),
                    'class' => 'short',
                    'element' => 'tester',
                    'textInput' => 1,
                    'button_icon' => 'search',
                    'button_class' => 'btn-mini btn-inverse',
                    'url' => '/sightingdb/search/',
                    'data_path' => 'Sightingdb.id'
                ),
                array(
                    'name' => __('Name'),
                    'data_path' => 'Sightingdb.name'
                ),
                array(
                    'name' => __('Owner'),
                    'sort' => 'owner',
                    'class' => 'short',
                    'data_path' => 'Sightingdb.owner'
                ),
                array(
                    'name' => __('Host'),
                    'sort' => 'host',
                    'data_path' => 'Sightingdb.host'
                ),
                array(
                    'name' => __('Port'),
                    'class' => 'short',
                    'data_path' => 'Sightingdb.port'
                ),
                array(
                    'name' => __('Namespace'),
                    'sort' => 'namespace',
                    'data_path' => 'Sightingdb.namespace'
                ),
                array(
                    'name' => __('Skip Proxy'),
                    'class' => 'short',
                    'element' => 'boolean',
                    'data_path' => 'Sightingdb.skip_proxy'
                ),
                array(
                    'name' => __('Skip SSL'),
                    'class' => 'short',
                    'element' => 'boolean',
                    'data_path' => 'Sightingdb.ssl_skip_verification'
                ),
                array(
                    'name' => __('Description'),
                    'data_path' => 'Sightingdb.description'
                ),
                array(
                    'name' => __('Restricted to'),
                    'class' => 'short',
                    'element' => 'org',
                    'data_path' => 'SightingdbOrg.{n}.Organisation'
                )
            ),
            'title' => __('SightingDB index'),
            'description' => __('SightingDB is an alternate sighting database that MISP interconnects with. Configure connections to sighting databases below.'),
            'actions' => array(
                array(
                    'url' => '/sightingdb/edit',
                    'url_params_data_paths' => array(
                        'Sightingdb.id'
                    ),
                    'icon' => 'edit'
                ),
                array(
                    'url' => '/sightingdb/delete',
                    'url_params_data_paths' => array(
                        'Sightingdb.id'
                    ),
                    'postLink' => 1,
                    'postLinkConfirm' => __('Are you sure you want to remove the connection to this SightingDB?'),
                    'icon' => 'trash'
                )
            )
        )
    ));
    echo '</div>';
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'sightingdb', 'menuItem' => 'index'));
?>
<script type="text/javascript">
    var passedArgsArray = <?php echo $passedArgs; ?>;
    if (passedArgsArray['context'] === undefined) {
        passedArgsArray['context'] = 'pending';
    }
    $(document).ready(function() {
        $('#quickFilterButton').click(function() {
            runIndexQuickFilter('/context:' + passedArgsArray['context']);
        });
    });
</script>
