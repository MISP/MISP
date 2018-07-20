<div class="index">
    <h2<?php echo __('>Results of the import');?>: </h2>
    <h3><?php echo __('%s attributes created successfully, %s  indicators could not be mapped and saved.',count($attributes), count($fails));?></h3>
    <br /><br />
    <?php
if (0 != count($attributes)): ?>
    <h4><?php echo __('Successfully added attributes');?>:</h4>
    <table class="table table-striped table-hover table-condensed">
    <tr>
            <th><?php echo __('Uuid');?></th>
            <th><?php echo __('Category');?></th>
            <th><?php echo __('Type');?></th>
            <th><?php echo __('Value');?></th>
    </tr><?php
foreach ($attributes as $attribute): ?>
    <tr>
        <td class="short"><?php echo h($attribute['uuid']); ?>&nbsp;</td>
        <td class="short"><?php echo h($attribute['category']); ?>&nbsp;</td>
        <td class="short"><?php echo h($attribute['type']); ?>&nbsp;</td>
        <td class="short"><?php echo h($attribute['value']); ?>&nbsp;</td>
    </tr><?php
endforeach; ?>
</table>
<?php
endif;?>
<?php
if (isset($fails)):?>
    <br /><br />
    <h4><?php echo __('Failed indicators');?>:</h4>
    <table class="table table-striped table-hover table-condensed">
    <tr>
            <th><?php echo __('Uuid');?></th>
            <th><?php echo __('Search term');?></th>
            <th><?php echo __('Content');?></th>
    </tr><?php
foreach ($fails as $fail): ?>
    <tr>
        <td class="short"><?php echo h($fail['uuid']); ?>&nbsp;</td>
        <td class="short"><?php echo h($fail['search']); ?>&nbsp;</td>
        <td class="short"><?php echo h($fail['value']); ?>&nbsp;</td>
    </tr><?php
endforeach; ?>
</table><br /><br />
<div class="visualisation">
<h4><?php echo __('Visualisation');?>:</h4>
<?php
endif;
foreach ($graph as $line): ?>
    <div style="white-space:pre-wrap; color: <?php echo ($line[1] ? 'green' : 'red'); ?>"><?php echo h($line[0]); ?>
    </div>
<?php
endforeach; ?>
</div>
</div>
<?php
    $event['Event']['id'] = $eventId;
    $event['Event']['published'] = 0;
    echo $this->element('side_menu', array('menuList' => 'event', 'menuItem' => 'addIOC', 'event' => $event));
?>
