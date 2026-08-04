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
    $table_data[] = array(
        'key' => __('Name'),
        'html' => sprintf(
            '%s %s',
            h($decaying_model['DecayingModel']['name']),
            $decaying_model['DecayingModel']['default'] ? '<img src="' . $baseurl . '/img/MISP.png" width="24" height="24" style="padding-bottom:3px;" title="' . __('Default Model from MISP Project') . '" />' : ''
        )
    );
    $table_data[] = array('key' => __('Description'), 'value' => $decaying_model['DecayingModel']['description']);
    if (isset($decaying_model['DecayingModel']['parameters']['base_score_config']) && empty($decaying_model['DecayingModel']['parameters']['base_score_config'])) {
        $decaying_model['DecayingModel']['parameters']['base_score_config'] = new stdClass(); // force output to be {} instead of []
        }
    $table_data[] = array('key' => __('Version'), 'value' => $decaying_model['DecayingModel']['version']);
    $table_data[] = array(
        'key' => __('All orgs'),
        'html' => '<i class="fas fa-' . ($decaying_model['DecayingModel']['all_orgs'] ? 'check' : 'times') . '"></i>'
    );
    $table_data[] = array(
        'key' => __('Enabled'),
        'html' => '<i class="fas fa-' . ($decaying_model['DecayingModel']['enabled'] ? 'check' : 'times') . '"></i>'
    );
    $table_data[] = array(
        'key' => __('Formula'),
        'html' => h($decaying_model['DecayingModel']['formula']) . (
            isset($available_formulas[$decaying_model['DecayingModel']['formula']]['description']) ? sprintf(' <i class="fas fa-question-circle" data-toggle="tooltip" title="%s"></i>', h($available_formulas[$decaying_model['DecayingModel']['formula']]['description'])) :  ''
        )
    );
    $table_data[] = array('key' => __('Parameters'), 'value' => json_encode($decaying_model['DecayingModel']['parameters']), 'class' => 'json-transform');
    $table_data[] = array('key' => __('Reference(s)'), 'html' => implode('<br/>', (empty($decaying_model['DecayingModel']['ref']) ? array() : h($decaying_model['DecayingModel']['ref']))));
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
    $('[data-toggle="tooltip"]').tooltip({placement: 'right'});
});
</script>
<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'decayingModel', 'menuItem' => 'view'));
?>
