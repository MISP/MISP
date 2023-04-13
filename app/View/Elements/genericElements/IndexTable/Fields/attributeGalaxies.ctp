<?php
$attribute = $row['Attribute'];
$event = $row['Event'];

echo '<div id="attribute_' . intval($attribute['id']) . '_galaxy">';
echo $this->element('galaxyQuickViewNew', array(
    'data' => !empty($attribute['Galaxy']) ? $attribute['Galaxy'] : array(),
    'event' => ['Event' => $event],
    'target_id' => $attribute['id'],
    'target_type' => 'attribute',
));
echo '</div>';
