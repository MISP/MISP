<?php
    $table_data = array();
    $table_data[] = array('key' => __('ID'), 'value' => $template['ObjectTemplate']['id']);
    $table_data[] = array('key' => __('Name'), 'value' => $template['ObjectTemplate']['name'] ? $template['ObjectTemplate']['name'] : $template['ObjectTemplate']['type']);
    $table_data[] = array('key' => __('Organisation'), 'value' => $template['Organisation']['name']);
    $table_data[] = array('key' => __('UUID'), 'value' => $template['ObjectTemplate']['uuid']);
    $table_data[] = array('key' => __('Version'), 'value' => $template['ObjectTemplate']['version']);
    $table_data[] = array('key' => __('Meta-category'), 'value' => $template['ObjectTemplate']['meta-category']);
    if (!empty($template['ObjectTemplate']['description'])) {
        $table_data[] = array('key' => __('Description'), 'value' => $template['ObjectTemplate']['description']);
    }
    if (!empty($template['ObjectTemplate']['requirements'])) {
        $requirements_contents = array();
        foreach ($template['ObjectTemplate']['requirements'] as $group => $requirements) {
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
        '<div class="roles view"><div class="row-fluid"><div class="span8" style="margin:0px;">%s</div></div>%s</div>%s',
        sprintf(
            '<h2>%s %s</h2>%s',
            h(ucfirst($template['ObjectTemplate']['name'])),
            __(' Object Template'),
            $this->element('genericElements/viewMetaTable', array('table_data' => $table_data))
        ),
        '<div id="ajaxContent" style="width:100%;"></div>',
        $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'objectTemplates', 'menuItem' => 'view'))
    );

?>
<script type="text/javascript">
<?php
    $startingTab = 'all';
?>
$(function () {
    objectTemplateViewContent('<?php echo $startingTab; ?>', '<?php echo h($id);?>');
});
</script>
