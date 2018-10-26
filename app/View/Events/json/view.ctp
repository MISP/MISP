<?php
App::uses('JSONConverterTool', 'Tools');
$converter = new JSONConverterTool();
echo $converter->convert($event);
