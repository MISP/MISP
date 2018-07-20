<div class="eventAddXML index">
    <h2><?php echo __('Add From MISP Export Result');?></h2>
    <table class="table table-striped table-hover table-condensed">
    <tr>
            <th><?php echo __('Event info');?></th>
            <th><?php echo __('Result');?></th>
            <th><?php echo __('Details');?></th>

    </tr>
<?php
    App::uses('JSONConverterTool', 'Tools');
    $converter = new JSONConverterTool();
    foreach ($results as &$result):
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
        if (!empty($result['validationIssues'])) $result['validationIssues'] = $converter->arrayPrinter($result['validationIssues']);
        else $result['validationIssues'] = false;
?>
        <tr>
            <td class="short"><?php echo h($result['info']); ?>&nbsp;</td>
            <td class="short" style="color:<?php echo $colour; ?>"><?php echo h($status); ?>&nbsp;</td>
            <td class="short">
                <?php
                    if ($result['validationIssues']) echo nl2br(h($result['validationIssues']));
                    echo nl2br(h($text));
                    if (0 !== ($result['id'])) echo ' <a href="' . $baseurl . '/events/view/' . h($result['id']) . '">' . __('Event ') . h($result['id']) . '</a>';
                ?>
                &nbsp;
            </td>
        </tr>
<?php
    endforeach;
?>
    </table>
</div>
<?php
    echo $this->element('side_menu', array('menuList' => 'event-collection', 'menuItem' => 'addMISPExport'));
?>
