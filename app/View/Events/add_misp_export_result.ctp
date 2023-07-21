<div class="index">
    <h2><?php echo __('Add From MISP Export Result');?></h2>
    <table class="table table-striped table-hover table-condensed">
    <tr>
        <th><?php echo __('Event info');?></th>
        <th><?php echo __('Result');?></th>
        <th><?php echo __('Details');?></th>
    </tr>
<?php
    App::uses('JSONConverterTool', 'Tools');
    foreach ($results as $result):
        if ($result['result'] === false) {
            $status = __('Failed');
        } else {
            $status = ucfirst($result['result']);
        }
        $text = '';
        $colour = 'red';
        if ($result['result'] === true) {
            $colour = 'green';
            $status = __('OK');
            $text = __('Event created.');
        } else if (is_numeric($result['result'])) {
            $text = __('Event with this UUID already exists.');
        }
        if (!empty($result['validationIssues'])) {
            $result['validationIssues'] = JSONConverterTool::arrayPrinter($result['validationIssues']);
        } else {
            $result['validationIssues'] = false;
        }
?>
        <tr>
            <td class="short"><?php echo h($result['info']); ?></td>
            <td class="short" style="color:<?php echo $colour; ?>"><?php echo h($status); ?></td>
            <td class="short">
                <?php
                    if ($result['validationIssues']) echo nl2br(h($result['validationIssues']), false);
                    echo nl2br(h($text), false);
                    if (0 !== ($result['id'])) echo ' <a href="' . $baseurl . '/events/view/' . h($result['id']) . '">' . __('Event %s', h($result['id'])) . '</a>';
                ?>
            </td>
        </tr>
<?php
    endforeach;
?>
    </table>
</div>
<?= $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event-collection', 'menuItem' => 'import_from'));

