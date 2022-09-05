<?php
/*
 *  echo $this->element('/genericElements/IndexTable/index_table', array(
 *      'top_bar' => (
 *          // search/filter bar information compliant with ListTopBar
 *      ),
 *      'data' => array(
            // the actual data to be used
 *      ),
 *      'fields' => array(
 *          // field list with information for the paginator
 *      ),
 *      'title' => optional title,
 *      'description' => optional description
 *  ));
 *
 */
    echo '<div class="index">';
    echo $this->element('/genericElements/IndexTable/index_table', array(
        'data' => array(
            'data' => $hits,
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
                    'name' => __('Id'),
                    'sort' => 'id',
                    'class' => 'short',
                    'data_path' => 'Feed.id'
                ),
                array(
                    'name' => __('Type'),
                    'class' => 'short',
                    'sort' => 'type',
                    'data_path' => 'Feed.type'
                ),
                array(
                    'name' => __('Name'),
                    'class' => 'short',
                    'sort' => 'name',
                    'data_path' => 'Feed.name'
                ),
                array(
                    'name' => __('Feed URL'),
                    'sort' => 'url',
                    'data_path' => 'Feed.url'
                ),
                array(
                    'name' => __('Link to correlation'),
                    'element' => 'links',
                    'data_path' => 'Feed.direct_urls',
                    'class' => 'action'
                )
            ),
            'title' => __('Feed Cache Search'),
            'description' => __('Search for values potentially contained in the cached feeds and servers.')
        )
    ));
    echo '</div>';
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'feeds', 'menuItem' => 'searchCaches'));
?>
<script type="text/javascript">
    var passedArgsArray = <?php echo $passedArgs; ?>;
    $(document).ready(function() {
        $('#quickFilterButton').click(function() {
            runIndexQuickFilter();
        });
    });
</script>
