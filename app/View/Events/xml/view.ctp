<?php
App::uses('XMLConverterTool', 'Tools');
$converter = new XMLConverterTool();
echo '<?xml version="1.0" encoding="UTF-8"?>' . PHP_EOL . '<response>' . PHP_EOL;
echo $converter->event2XML($event) . PHP_EOL;
echo '<xml_version>' . $mispVersion . '</xml_version>';
echo '</response>' . PHP_EOL;
