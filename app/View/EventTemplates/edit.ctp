<?php
echo $this->element('eventTemplates/builder/shell', [
    'data' => isset($data) ? $data : null,
]);
