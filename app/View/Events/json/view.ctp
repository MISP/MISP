<?php
App::uses('JSONConverterTool', 'Tools');
foreach (JSONConverterTool::streamConvert($event) as $part) {
    echo $part;
}
