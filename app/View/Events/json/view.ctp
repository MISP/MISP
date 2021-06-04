<?php
App::uses('JSONConverterTool', 'Tools');
$converter = new JSONConverterTool();
foreach ($converter->streamConvert($event) as $part) {
    echo $part;
}
