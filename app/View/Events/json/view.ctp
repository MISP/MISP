<?php
App::uses('JSONConverterTool', 'Tools');
$converter = new JSONConverterTool();
echo $converter->event2JSON($event);
