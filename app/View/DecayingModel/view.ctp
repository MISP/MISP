<?php
    $table_data = array();
    $table_data[] = array('key' => __('Model ID'), 'value' => $decayingModel['DecayingModel']['id']);
    $table_data[] = array(
        'key' => __('Creator org'),
        'html' => sprintf(
            '<a href="%s/organisations/view/%s">%s</a>',
            $baseurl,
            h($decayingModel['DecayingModel']['org_id']),
            h($decayingModel['DecayingModel']['org_id'])
        )
    );
    $table_data[] = array('key' => __('Name'), 'value' => $decayingModel['DecayingModel']['name']);
    $table_data[] = array('key' => __('Description'), 'value' => $decayingModel['DecayingModel']['description']);
    $table_data[] = array('key' => __('Parameters'), 'value' => json_encode($decayingModel['DecayingModel']['parameters']), 'class' => 'json-transform');
?>
<div class='view'>
    <div class="row-fluid">
        <div class="span8">
            <?php echo $this->element('genericElements/viewMetaTable', array('table_data' => $table_data)); ?>
        </div>
    </div>
</div>

<script>
$(document).ready(function() {
    $('td.meta_table_value.json-transform').each(function(i) {
        var parsedJson = syntaxHighlightJson($(this).text().trim());
        $(this).html(parsedJson);
    });
});
</script>
<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'decayingModel', 'menuItem' => 'view'));
?>
