<?php $appendlen = 12; ?>
<?php //foreach ($events as $event): ?>
Event       : <?php echo $event['Event']['id']; ?> 
Date        : <?php echo $event['Event']['date']; ?> 
Reported by : <?php echo Sanitize::html($event['Event']['org']); ?> 
Risk        : <?php echo $event['Event']['risk']; ?> 
Signatures  :
<?php if (!empty($event['Signature'])):
    $i = 0;
    foreach ($event['Signature'] as $signature): ?>
- <?php echo $signature['type']; echo str_repeat(' ', $appendlen - 2 - strlen( $signature['type'])); ?>
: <?php echo Sanitize::html($signature['value']);?> 
<?php endforeach; ?><?php endif; ?>
Extra info  : 
<?php echo Sanitize::html($event['Event']['info']); ?> 
 
<?php //endforeach; ?>
