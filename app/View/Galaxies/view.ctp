<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'galaxies', 'menuItem' => 'view'));

    $table_data = array();
    $table_data[] = array('key' => __('Galaxy ID'), 'value' => $galaxy['Galaxy']['id']);
    $table_data[] = array('key' => __('Name'), 'value' => $galaxy['Galaxy']['name']);
    $table_data[] = array('key' => __('Namespace'), 'value' => $galaxy['Galaxy']['namespace']);
    $table_data[] = array('key' => __('UUID'), 'value' => $galaxy['Galaxy']['uuid']);
    $table_data[] = array('key' => __('Description'), 'value' => $galaxy['Galaxy']['description']);
    $table_data[] = array('key' => __('Version'), 'value' => $galaxy['Galaxy']['version']);
    $kco = '';
    if (isset($galaxy['Galaxy']['kill_chain_order'])) {
        $kco = '<strong>' . __('Kill chain order') . '</strong> <span class="useCursorPointer fa fa-expand" onclick="$(\'#killChainOrder\').toggle(\'blind\')"></span>';
        $kco .= '<div id="killChainOrder" class="hidden" style="border: 1px solid #000; border-radius: 5px; padding: 3px; background: #f4f4f4; margin-left: 20px;">' . json_encode($galaxy['Galaxy']['kill_chain_order']) . '</div>';
    }
?>

<div class="view">
    <div class="row-fluid">
        <div class="span8">
            <h2>
                <span class="<?php echo $this->FontAwesome->findNamespace($galaxy['Galaxy']['icon']); ?> fa-<?php echo h($galaxy['Galaxy']['icon']); ?>"></span>&nbsp;
                <?php echo h($galaxy['Galaxy']['name']); ?> galaxy
            </h2>
            <?php echo $this->element('genericElements/viewMetaTable', array('table_data' => $table_data)); ?>
            <?php echo $kco; ?>
        </div>
    </div>
    <div id="clusters_content"></div>
</div>

<script type="text/javascript">
$(function () {
    <?php
        $uri = $baseurl . "/galaxy_clusters/index/" . $galaxy['Galaxy']['id'];
        if (isset($passedArgsArray) && isset($passedArgsArray['context']) && $passedArgsArray['context'] == 'fork_tree') {
            $uri = '/galaxies/forkTree/' . $galaxy['Galaxy']['id'];
        } elseif (isset($passedArgsArray) && isset($passedArgsArray['context']) && $passedArgsArray['context'] == 'relations') {
            $uri = '/galaxies/relationsGraph/' . $galaxy['Galaxy']['id'];
        } elseif (isset($passedArgsArray) && isset($passedArgsArray['context'])) {
            $uri .= '/context:' . $passedArgsArray['context'];
            if (isset($passedArgsArray) && isset($passedArgsArray['searchall'])) {
                $uri .= '/searchall:' . $passedArgsArray['searchall'];
            }
        }
    ?>
    $.get("<?php echo h($uri);?>", function(data) {
        $("#clusters_content").html(data);
    }).fail(xhrFailCallback);

    var $kco = $('#killChainOrder');
    if ($kco && $kco.length > 0) {
        var j = syntaxHighlightJson($kco.text(), 8)
        $kco.html(j);
    }
});
</script>
