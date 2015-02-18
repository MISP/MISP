<?php
App::uses('JSONConverterTool', 'Tools');
$converter = new JSONConverterTool();
echo json_encode($converter->event2JSON($event));