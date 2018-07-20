<table id="server-settings-container" class="table table-hover table-condensed" style="border:1px solid #dddddd; margin-top:1px; width:100%; padding:10px">
<tr>
        <th>Test</th>
        <th>Value</th>
        <th>Description</th>
</tr>
<?php
    $health = array(0 => __('Critical, your MISP instance requires immediate attention.'), 1 => __('Issues found, it is recommended that you resolve them.'), 2 => __('Good, but there are some optional settings that are incorrect / not set.'), 3 => __('In perfect health.'));
    $colour = '';
    if ($diagnostic_errors > 0) $issues['overallHealth'] = 0;
    if ($issues['overallHealth'] < 3) $colour = 'background-color:' . $priorityErrorColours[$issues['overallHealth']] . ';';
    if ($issues['overallHealth'] == 0 || $issues['overallHealth'] == 2) $colour .= 'color:white;';
?>
<tr>
    <td style="<?php echo $colour;?>"><?php echo __('Overall health');?></td>
    <td style="<?php echo $colour;?>"><?php echo h($health[$issues['overallHealth']]);?></td>
    <td style="<?php echo $colour;?>"><?php echo __('The overall health of your instance depends on the most severe unresolved issues.');?></td>
</tr>
<?php
    foreach ($issues['errors'] as $k => $v):
        $colour = '';
        if ($k < 3 && $v['value'] > 0) $colour = 'background-color:' . $priorityErrorColours[$k] . ';';
        if (($k == 0 || $k == 2) && $v['value'] > 0) $colour .= 'color:white;';
?>
<tr>
    <td style="<?php echo $colour; ?>"><?php echo h($priorities[$k]) . __(' settings incorrectly or not set');?></td>
    <td style="<?php echo $colour; ?>"><?php echo h($v['value']);?><?php echo __(' incorrect settings.');?></td>
    <td style="<?php echo $colour; ?>"><?php echo h($v['description']);?></td>
</tr>
<?php endforeach; ?>
<tr>
    <?php $colour = ($diagnostic_errors > 0 ? 'background-color:red;color:white;' : '');?>
    <td style="<?php echo $colour; ?>"><?php echo __('Critical issues revealed by the diagnostics');?></td>
    <td style="<?php echo $colour; ?>"><?php echo h($diagnostic_errors);?><?php echo __(' issues detected.');?></td>
    <td style="<?php echo $colour; ?>"><?php echo __('Issues revealed here can be due to incorrect directory permissions or not correctly installed dependencies.');?></td>
</tr>
</table>
