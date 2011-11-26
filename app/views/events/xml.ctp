<?php echo "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n"; ?>
<CyDefSIG>
<?php foreach ($events as $event): ?>
    <event>
        <id><?php echo $event['Event']['id']; ?></id>
        <org><?php echo Sanitize::html($event['Event']['org']); ?></org>
        <date><?php echo $event['Event']['date']; ?></date>
        <risk><?php echo $event['Event']['risk']; ?></risk>
        <info><?php echo Sanitize::html($event['Event']['info']); ?></info>
<?php if (!empty($event['Signature'])):
            $i = 0;
            foreach ($event['Signature'] as $signature): ?>
        <sig type="<?php echo $signature['type'];?>"><?php echo Sanitize::html($signature['value']);?></sig>
<?php endforeach; ?><?php endif; ?>
    </event>
<?php endforeach; ?>
</CyDefSIG>