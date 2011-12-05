<?php echo $this->Xml->header(); ?>
<CyDefSIG>
<?php echo $this->Xml->serialize($events, array('format' => 'tags')); ?>
</CyDefSIG>