<?php
echo $this->element('eventTemplates/userForm/shell', array(
    'data' => $data,
    'definition' => $definition,
    'objectRelationSpecs' => $objectRelationSpecs,
    'isPreview' => true,
    'viewMode' => isset($viewMode) ? $viewMode : 'all',
));
