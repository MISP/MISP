<?php
$value = $this->Hash->extract($data, $field['path'])[0];
echo $this->Time->time($value);
