<?php $appendlen = 12; ?>
<?php //foreach ($events as $event): ?>
Event       : <?php echo $event['Event']['id']; ?>
Date        : <?php echo $event['Event']['date']; ?>
Reported by : <?php echo h($event['Event']['org']); ?>
Risk        : <?php echo $event['Event']['risk']; ?>
Attributes  :
<?php if (!empty($event['Attribute'])):
	$i = 0;
	foreach ($event['Attribute'] as $attribute): ?>
- <?php echo $attribute['type']; echo str_repeat(' ', $appendlen - 2 - strlen( $attribute['type'])); ?>
: <?php echo h($attribute['value']);?>
<?php endforeach; ?><?php endif; ?>
Extra info  :
<?php echo h($event['Event']['info']); ?>

<?php //endforeach;
