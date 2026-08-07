<?php
echo $this->element('eventTemplates/userForm/shell', [
    'data' => $data,
    'definition' => $definition,
    'objectRelationSpecs' => $objectRelationSpecs,
    'isPreview' => true,
]);
