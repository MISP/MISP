<?php
    $table_data = array();
    $table_data[] = array('key' => __('Model ID'), 'value' => $decaying_model['DecayingModel']['id']);
    $table_data[] = array(
        'key' => __('Creator org'),
        'html' => sprintf(
            '<a href="%s/organisations/view/%s">%s</a>',
            $baseurl,
            h($decaying_model['DecayingModel']['org_id']),
            h($decaying_model['DecayingModel']['org_id'])
        )
    );
    $table_data[] = array('key' => __('Name'), 'value' => $decaying_model['DecayingModel']['name']);
    $table_data[] = array('key' => __('Description'), 'value' => $decaying_model['DecayingModel']['description']);
    $table_data[] = array('key' => __('Parameters'), 'value' => json_encode($decaying_model['DecayingModel']['parameters']), 'class' => 'json-transform');
    $table_data[] = array('key' => __('Formula'), 'value' => $decaying_model['DecayingModel']['formula']);
    $table_data[] = array('key' => __('Reference(s)'), 'html' => implode('<br/>', (empty($decaying_model['DecayingModel']['ref']) ? array() : $decaying_model['DecayingModel']['ref'])));
    $table_data[] = array('key' => __('Associated types'), 'value' => json_encode($decaying_model['DecayingModel']['attribute_types']), 'class' => 'json-transform');
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
