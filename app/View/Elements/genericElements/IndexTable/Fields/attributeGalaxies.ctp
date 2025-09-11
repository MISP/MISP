<?php
$attribute = isset($row['Attribute']) ? $row['Attribute'] : $row;
$event = isset($row['Event']) ? $row['Event'] : (isset($parent['Event']) ? $parent['Event'] : null);
echo '<div id="attribute_' . intval($attribute['id']) . '_galaxy">';
echo $this->element('galaxyQuickView', array(
    'data' => !empty($attribute['Galaxy']) ? $attribute['Galaxy'] : array(),
    'event' => ['Event' => $event],
    'target_id' => $attribute['id'],
    'target_type' => 'attribute',
));
echo '</div>';
