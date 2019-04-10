<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'galaxies', 'menuItem' => 'view_cluster'));
?>
<div class="galaxy view">
    <div class="row-fluid">
        <div class="span8">
            <h2>
                <?php echo isset($cluster['Galax']['name']) ? h($cluster['Galaxy']['name']) : h($cluster['GalaxyCluster']['type']) . ': ' . $cluster['GalaxyCluster']['value']; ?>
            </h2>
            <dl>
                <dt><?php echo __('Cluster ID');?></dt>
                <dd><?php echo h($cluster['GalaxyCluster']['id']); ?></dd>
                <dt><?php echo __('Name');?></dt>
                <dd><?php echo h($cluster['GalaxyCluster']['value']); ?></dd>
                <dt><?php echo __('Parent Galaxy');?></dt>
                <dd><?php echo $cluster['Galaxy']['name'] ? h($cluster['Galaxy']['name']) : h($cluster['Galaxy']['type']); ?></dd>
                <dt><?php echo __('Description');?></dt>
                <dd><?php echo h($cluster['GalaxyCluster']['description']); ?>&nbsp;</dd>
                <dt><?php echo __('UUID');?></dt>
                <dd><?php echo h($cluster['GalaxyCluster']['uuid']); ?>&nbsp;</dd>
                <dt><?php echo __('Collection UUID');?></dt>
                <dd><?php echo h($cluster['GalaxyCluster']['collection_uuid']); ?>&nbsp;</dd>
                <dt><?php echo __('Source');?></dt>
                <dd><?php echo h($cluster['GalaxyCluster']['source']); ?>&nbsp;</dd>
                <dt><?php echo __('Authors');?></dt>
                <dd>
                    <?php
                        $authors = $cluster['GalaxyCluster']['authors'];
                        if (!empty($authors)) {
                            echo implode(', ', $authors);
                        } else {
                            echo __('N/A');
                        }
                    ?>
                </dd>
                <dt><?php echo __('Connector tag');?></dt>
                <dd><?php echo h($cluster['GalaxyCluster']['tag_name']); ?></dd>
                <dt><?php echo __('Events');?></dt>
                <dd>
                    <?php
                        if (isset($cluster['GalaxyCluster']['tag_count'])):
                    ?>
                        <a href="<?php echo $baseurl; ?>/events/index/searchtag:<?php echo h($cluster['GalaxyCluster']['tag_id']); ?>"><?php echo h($cluster['GalaxyCluster']['tag_count']); ?> event(s)</a>
                    <?php
                        else:
                            echo '0';
                        endif;
                    ?>
                </dd>
            </dl>
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
