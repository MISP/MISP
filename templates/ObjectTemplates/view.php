<?php
$table_data = array();
$table_data[] = array('key' => __('ID'), 'value' => $template['id']);
$table_data[] = array('key' => __('Name'), 'value' => $template['name'] ? $template['name'] : $template['type']);
$table_data[] = array('key' => __('Organisation'), 'value' => $template['Organisation']['name']);
$table_data[] = array('key' => __('UUID'), 'value' => $template['uuid']);
$table_data[] = array('key' => __('Version'), 'value' => $template['version']);
$table_data[] = array('key' => __('Meta-category'), 'value' => $template['meta_category']);
if (!empty($template['description'])) {
    $table_data[] = array('key' => __('Description'), 'value' => $template['description']);
}
if (!empty($template['requirements'])) {
    $requirements_contents = array();
    foreach ($template['requirements'] as $group => $requirements) {
        $requirements_contents[] = sprintf(
            '<span class="bold">%s</span>',
            h($group)
        );
        foreach ($requirements as $requirement) {
            sprintf(
                $requirements_contents[] = sprintf(
                    '<span>&nbsp;&nbsp;%s</span>',
                    h($requirement)
                )
            );
        }
    }
    $table_data[] = array('key' => __('Requirements'), 'html' => implode('<br>', $requirements_contents));
}
echo sprintf(
    '<div class="roles view"><div class="row-fluid"><div class="span8" style="margin:0px;">%s</div></div>%s</div>',
    sprintf(
        '<h2>%s %s</h2>%s',
        h(ucfirst($template['name'])),
        __(' Object Template'),
        $this->element('genericElements/viewMetaTable', array('table_data' => $table_data))
    ),
    '<div id="ajaxContent" style="width:100%;"></div>'
);

?>
<script type="text/javascript">
    <?php
    $startingTab = 'all';
    ?>

    function objectTemplateViewContent(context, id) {
        var url = "/object-template-elements/viewElements/" + id + "/" + context;
        AJAXApi.quickFetchURL(url, {})
            .then(function(data) {
                $('#ajaxContent').html(data);
            })
            .catch((e) => {
                UI.toast({
                    variant: 'danger',
                    text: '<?= __('An error has occurred, please reload the page.') ?>'
                })
            });
        // xhr({
        //     url: url,
        //     type:'GET',
        //     error: function(){
        //         $('#ajaxContent').html('An error has occurred, please reload the page.');
        //     },
        //     success: function(response){
        //         $('#ajaxContent').html(response);
        //     },
        // });

    }
    $(function() {
        objectTemplateViewContent('<?php echo $startingTab; ?>', '<?php echo h($id); ?>');
    });
</script>