<?php
    echo $this->element('side_menu', array('menuList' => 'galaxies', 'menuItem' => 'view_cluster'));
?>
<div class="galaxy view">
    <div class="row-fluid">
        <div class="span8">
            <h2>
                <?php echo isset($cluster['Galax']['name']) ? h($cluster['Galaxy']['name']) : h($cluster['GalaxyCluster']['type']) . ': ' . $cluster['GalaxyCluster']['value']; ?>
            </h2>
            <dl>
                <dt>Cluster ID</dt>
                <dd><?php echo h($cluster['GalaxyCluster']['id']); ?></dd>
                <dt>Name</dt>
                <dd><?php echo h($cluster['GalaxyCluster']['value']); ?></dd>
                <dt>Parent Galaxy</dt>
                <dd><?php echo $cluster['Galaxy']['name'] ? h($cluster['Galaxy']['name']) : h($cluster['Galaxy']['type']); ?></dd>
                <dt>Description</dt>
                <dd><?php echo h($cluster['GalaxyCluster']['description']); ?>&nbsp;</dd>
                <dt>Source</dt>
                <dd><?php echo h($cluster['GalaxyCluster']['source']); ?>&nbsp;</dd>
                <dt>Authors</dt>
                <dd>
                    <?php
                        $authors = $cluster['GalaxyCluster']['authors'];
                        if (!empty($authors)) {
                            echo implode(', ', $authors);
                        } else {
                            echo 'N/A';
                        }
                    ?>
                </dd>
                <dt>Connector tag</dt>
                <dd><?php echo h($cluster['GalaxyCluster']['tag_name']); ?></dd>
                <dt>Events</dt>
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
    <div class="row-fluid">
        <div id="elements_div" class="span8"></div>
    </div>
</div>
<script type="text/javascript">
$(document).ready(function () {
    $.get("/galaxy_elements/index/<?php echo $cluster['GalaxyCluster']['id']; ?>", function(data) {
        $("#elements_div").html(data);
    });
});
</script>
