<?php
echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'sync', 'menuItem' => 'id_translator'));
echo $this->element('/genericElements/Form/genericForm', array(
    'form' => $this->Form,
    'data' => array(
        'title' => __('Event ID translator'),
        'description' => __('Allows to translate a local ID into the corresponding event ID on sync servers configured.'),
        'model' => 'Event',
        'fields' => array(
            array(
                "field" => "uuid",
                "label" => __("Event ID or UUID"),
                "type" => "text",
                "placeholder" => __("1234"),
                "stayInLine" => true,
            ),
            array(
                "field" => "local",
                "label" => __("Referencing an event which is"),
                "default" => "local",
                "options" => array("local" => __("local"), "remote" => __("remote")),
                "type" => "select",
                "stayInLine" => true,
            ),
            array(
                "field" => "Server.id",
                "div" => "input select optional-server-select hide",
                "options" => $servers,
                "label" => __("ID referenced on server"),
                "type" => "select",
            )
        ),
        "submit" => array(
            "action" => "idTranslator",
        ),
    )
));
echo '<div class="view">';
echo $this->Flash->render();
if (isset($remote_events) && isset($local_event)) {
    $table_data = array();
    $table_data[] = array('key' => __('UUID'), 'value' => $local_event['Event']['uuid']);
    $table_data[] = array('key' => __('Info'), 'value' => $local_event['Event']['info']);
    $link = '<a href="' . $baseurl . '/events/view/' . $local_event['Event']['id'] . '" rel="noreferrer noopener" target="_blank">' . $local_event['Event']['id'] . '</a>';
    $table_data[] = array('key' => __('Local ID'), 'html' => $link);
    foreach ($remote_events as $remote_event) {
        if ($remote_event['remote_id']) {
            $value = __('Remote ID:') . ' <a href="'.h($remote_event['url']).'" rel="noreferrer noopener" target="_blank">' . $remote_event['remote_id'] . '</a>';
            if ($isSiteAdmin) {
                $value .= ' (<a href="' . $baseurl . '/servers/previewEvent/' . $remote_event['server_id'] . '/' . $remote_event['remote_id'] . '">' . __('preview') .  '</a>)';
            }
            $table_data[] = array('key' => h($remote_event['server_name']), 'html' => $value);
        } else {
            $table_data[] = array('key' => h($remote_event['server_name']), 'value' => __('Not found or server unreachable'));
        }
    }
    echo $this->element('genericElements/viewMetaTable', array('table_data' => $table_data));
}
echo "</div>";
?>
<script type="text/javascript">
function IDTranslatorUISetup() {
    if($('#EventLocal').val() === "remote") {
        $(".optional-server-select").show();
    } else {
        $(".optional-server-select").hide();
    }
}
$(function() {
  IDTranslatorUISetup();
});
$("#EventLocal").change(function(){
    IDTranslatorUISetup();
});
</script>
