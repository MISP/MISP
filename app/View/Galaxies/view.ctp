<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'galaxies', 'menuItem' => 'view'));
?>
<div class="galaxy view">
    <div class="row-fluid">
        <div class="span8">
            <h2>
                <span class="<?php echo $this->FontAwesome->findNamespace($galaxy['Galaxy']['icon']); ?> fa-<?php echo h($galaxy['Galaxy']['icon']); ?>"></span>&nbsp;
                <?php echo h($galaxy['Galaxy']['name']); ?> galaxy
            </h2>
            <dl>
                <dt><?php echo __('Galaxy ID');?></dt>
                <dd><?php echo h($galaxy['Galaxy']['id']); ?></dd>
                <dt><?php echo __('Name');?></dt>
                <dd><?php echo $galaxy['Galaxy']['name'] ? h($galaxy['Galaxy']['name']) : h($galaxy['Galaxy']['type']); ?></dd>
                <dt><?php echo __('Namespace');?></dt>
                <dd><?php echo $galaxy['Galaxy']['namespace'] ? h($galaxy['Galaxy']['namespace']) : 'misp'; ?></dd>
                <dt><?php echo __('Uuid');?></dt>
                <dd><?php echo h($galaxy['Galaxy']['uuid']); ?></dd>
                <dt><?php echo __('Description');?></dt>
                <dd><?php echo h($galaxy['Galaxy']['description']); ?></dd>
                <dt><?php echo __('Version');?></dt>
                <dd><?php echo h($galaxy['Galaxy']['version']); ?></dd>

            </dl>
            <?php
            $kco = '';
            if (isset($galaxy['Galaxy']['kill_chain_order'])) {
                $kco = '<strong>' . __('Kill chain order') . '</strong> <span class="useCursorPointer fa fa-expand" onclick="$(\'#killChainOrder\').toggle(\'blind\')"></span>';
                $kco .= '<div id="killChainOrder" class="hidden" style="border: 1px solid #000; border-radius: 5px; padding: 3px; background: #f4f4f4; margin-left: 20px;">' . json_encode($galaxy['Galaxy']['kill_chain_order']) . '</div>';
            }
            echo $kco;
            ?>
        </div>
    </div>
    <div id="clusters_div"></div>
</div>
<script type="text/javascript">
$(document).ready(function () {
    <?php
    $uri = "/galaxy_clusters/index/" . $galaxy['Galaxy']['id'];
    if (isset($passedArgsArray)) $uri .= '/searchall:' . $passedArgsArray['all'];
    ?>
    $.get("<?php echo h($uri);?>", function(data) {
        $("#clusters_div").html(data);
    });

    var $kco = $('#killChainOrder');
    var j = syntaxHighlightJson($kco.text(), 8)
    $kco.html(j);
});
</script>
