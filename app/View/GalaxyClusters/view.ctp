<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'galaxies', 'menuItem' => 'view_cluster'));

    $extendedFromHtml = '';
    $extendFromLinks = array();
    if (!empty($cluster['GalaxyCluster']['extended_from'])) {
        $element = $this->element('genericElements/IndexTable/Fields/links', array(
            'url' => $baseurl . '/galaxy_clusters/view/',
            'row' => $cluster,
            'field' => array(
                'data_path' => 'GalaxyCluster.extended_from.GalaxyCluster.id',
                'title' => $cluster['GalaxyCluster']['extended_from']['GalaxyCluster']['value']
            ),
        ));
        $extendFromLinks[] = sprintf('<li>%s</li>', $element);
    }
    $extendedFromHtml = sprintf('<ul>%s</ul>', implode('', $extendFromLinks));

    $extendedByHtml = '';
    $extendByLinks = array();
    foreach($cluster['GalaxyCluster']['extended_by'] as $extendCluster) {
        $element = $this->element('genericElements/IndexTable/Fields/links', array(
            'url' => '/galaxy_clusters/view/',
            'row' => $extendCluster,
            'field' => array(
                'data_path' => 'GalaxyCluster.id',
                'title' => $extendCluster['GalaxyCluster']['value']
            ),
        ));
        $extendByLinks[] = sprintf('<li>%s</li>', $element);
    }
    $extendedByHtml = sprintf('<ul>%s</ul>', implode('', $extendByLinks));
    $table_data = array();
    $table_data[] = array('key' => __('Cluster ID'), 'value' => $cluster['GalaxyCluster']['id']);
    $table_data[] = array('key' => __('Name'), 'value' => $cluster['GalaxyCluster']['value']);
    $table_data[] = array('key' => __('Parent Galaxy'), 'value' => $cluster['Galaxy']['name'] ? $cluster['Galaxy']['name'] : $cluster['Galaxy']['type']);
    $table_data[] = array('key' => __('Description'), 'value' => $cluster['GalaxyCluster']['description']);
    $table_data[] = array('key' => __('UUID'), 'value' => $cluster['GalaxyCluster']['uuid']);
    $table_data[] = array('key' => __('Collection UUID'), 'value' => $cluster['GalaxyCluster']['collection_uuid']);
    $table_data[] = array('key' => __('Source'), 'value' => $cluster['GalaxyCluster']['source']);
    $table_data[] = array('key' => __('Authors'), 'value' => !empty($cluster['GalaxyCluster']['authors']) ? implode(', ', $cluster['GalaxyCluster']['authors']) : __('N/A'));
    $table_data[] = array('key' => __('Distribution'), 'value' => $cluster['GalaxyCluster']['distribution'] . ' TODO: Use distribution element!');
    $table_data[] = array(
        'key' => __('Owner Organisation'), 
        'html' => $this->OrgImg->getOrgImg(array('name' => $cluster['Org']['name'], 'id' => $cluster['Org']['id'], 'size' => 18), true),
    );
    $table_data[] = array(
        'key' => __('Creator Organisation'), 
        'html' => $this->OrgImg->getOrgImg(array('name' => $cluster['Orgc']['name'], 'id' => $cluster['Orgc']['id'], 'size' => 18), true),
    );
    $table_data[] = array('key' => __('Connector tag'), 'value' => $cluster['GalaxyCluster']['tag_name']);
    $table_data[] = array('key' => __('Events'), 'html' => isset($cluster['GalaxyCluster']['tag_count']) ? 
                        sprintf('<a href="%s">%s %s</a>', 
                            sprintf('%s/events/index/searchtag:%s', $baseurl, h($cluster['GalaxyCluster']['tag_id'])),
                            h($cluster['GalaxyCluster']['tag_count']),
                            __('event(s)')
                        ):
                        '<span>0</span>'
                    );
    $table_data[] = array('key' => __('Extended From'), 'html' => $extendedFromHtml);
    $table_data[] = array('key' => __('Extended By'), 'html' => $extendedByHtml);
?>

<div class='view'>
    <div class="row-fluid">
        <div class="span8">
            <h2>
                <?php echo isset($cluster['Galaxy']['name']) ? h($cluster['Galaxy']['name']) : h($cluster['GalaxyCluster']['type']) . ': ' . $cluster['GalaxyCluster']['value']; ?>
            </h2>
            <?php echo $this->element('genericElements/viewMetaTable', array('table_data' => $table_data)); ?>
        </div>
    </div>
    <div class="row-fuild">
        <div id="matrix_container"></div>
    </div>
    <div class="row-fluid">
        <div id="elements_div" class="span8"></div>
    </div>
</div>
<script type="text/javascript">
$(document).ready(function () {
    $.get("/galaxy_elements/index/<?php echo $cluster['GalaxyCluster']['id']; ?>", function(data) {
        $("#elements_div").html(data);
    });
    $.get("/galaxy_clusters/viewGalaxyMatrix/<?php echo $cluster['GalaxyCluster']['id']; ?>", function(data) {
        $("#matrix_container").html(data);
    });
});
</script>
