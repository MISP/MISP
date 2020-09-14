<?php
    $table_data = array();
    $table_data[] = array('key' => __('ID'), 'value' => $report['EventReport']['id']);
    $table_data[] = array('key' => __('UUID'), 'value' => $report['EventReport']['uuid']);
    $table_data[] = array('key' => __('Name'), 'value' => $report['EventReport']['name']);
    $table_data[] = array(
        'key' => __('Event ID'),
        'html' => sprintf('%s', sprintf(
            '<a href="%s">%s</a>',
            sprintf('%s%s%s', $baseurl, '/events/view/', h($report['EventReport']['event_id'])),
            h($report['EventReport']['event_id'])
        ))
    );
    $table_data[] = array(
        'key' => __('Distribution'),
        'value_class' => ($report['EventReport']['distribution'] == 0) ? 'privateRedText' : '',
        'html' => sprintf('%s',
            ($report['EventReport']['distribution'] == 4) ?
                sprintf('<a href="%s%s">%s</a>', $baseurl . '/sharing_groups/view/', h($report['SharingGroup']['id']), h($report['SharingGroup']['name'])) :
                h($distributionLevels[$report['EventReport']['distribution']])
        )
    );

    $table_data[] = array('key' => __('Timestamp'), 'value' => $report['EventReport']['timestamp']);
    $table_data[] = array('key' => __('Deleted'), 'value' => $report['EventReport']['deleted'] ? __('Yes') : __('No'));
?>

<div class='<?= !isset($ajax) || !$ajax ? 'view' : '' ?>'>
    <div class="row-fluid">
        <h2><?= h($report['EventReport']['name']) ?></h2>
        <div class="span8" style="margin-bottom: 10px;">
            <?php echo $this->element('genericElements/viewMetaTable', array('table_data' => $table_data)); ?>
        </div>
        <div class="clear">
            <h4>
                <?= __('Event Report content') ?>
            </h4>
            <?php 
                echo $this->element('EventReports/markdownEditor', array(
                    'markdown' => $report['EventReport']['content'],
                    'modelName' => 'EventReport',
                    'mardownModelFieldName' => 'content',
                    'eventid' => $report['EventReport']['event_id'],
                    'reportid' => $report['EventReport']['id'],
                    'webDependencies' => array('js' => array('markdownEditor/event-report'), 'css' => array('markdownEditor/event-report')),
                    'helpModal' => 'EventReports/markdownEditorHelpModal'
                ));
            ?>
        </div>
    </div>
    <div style="margin-bottom: 15px;"></div>
</div>
<script type="text/javascript">
$(document).ready(function () {
});
</script>


<?php
    if (!isset($ajax) || !$ajax) {
        echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'eventReports', 'menuItem' => 'view'));
    }
?>
