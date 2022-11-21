<?php
echo $this->element('ajaxTags', [
    'attributeId' => $attributeId,
    'tags' => $attributeTags,
    'tagAccess' => $isSiteAdmin || $mayModify,
    'localTagAccess' => $this->Acl->canModifyTag($event, true),
    'scope' => 'attribute'
]);

