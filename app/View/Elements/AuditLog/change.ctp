<?php
$removeActions = [
    AuditLog::ACTION_DELETE => true,
    AuditLog::ACTION_REMOVE_GALAXY_LOCAL => true,
    AuditLog::ACTION_REMOVE_GALAXY => true,
    AuditLog::ACTION_REMOVE_TAG => true,
    AuditLog::ACTION_REMOVE_TAG_LOCAL => true,
];

$full = isset($full) ? $full : false;
$formatValue = function($field, $value) use ($full) {
    if ((strpos($field, 'timestamp') !== false || in_array($field, ['expiration', 'created', 'date_created'], true)) && is_numeric($value)) {
        $date = date('Y-m-d H:i:s', $value);
        if ($date !== false) {
            return '<span title="Original value: ' . h($value) . '">' . h($date) . '</span>';
        }
    } else if ($field === 'last_seen' || $field === 'first_seen') {
        $ls_sec = intval($value / 1000000); // $ls is in micro (10^6)
        $ls_micro = $value % 1000000;
        $ls_micro = str_pad($ls_micro, 6, "0", STR_PAD_LEFT);
        $ls = $ls_sec . '.' . $ls_micro;
        $date = DateTime::createFromFormat('U.u', $ls)->format('Y-m-d\TH:i:s.u');
        return '<span title="Original value: ' . h($value) . '">' . h($date) . '</span>';
    }

    if ($full && is_string($value) && !empty($value) && ($value[0] === '{' || $value[0] === '[') && json_decode($value) !== null) {
        return '<span class="json">' . h($value) . '</span>';
    }

    if (!$full && mb_strlen($value) > 64) {
        $value = mb_substr($value, 0, 64) . '...';
    }
    return h(json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
};

if (is_array($item['AuditLog']['change'])) {
    foreach ($item['AuditLog']['change'] as $field => $values) {
        echo '<span class="json_key">' . h($field) . ':</span> ';
        if (isset($removeActions[$item['AuditLog']['action']])) {
            echo '<span class="json_string">' . $formatValue($field, $values) . '</span> <i class="fas fa-arrow-right json_null"></i> <i class="fas fa-times json_string"></i><br>';
        } else {
            if (is_array($values)) {
                echo '<span class="json_string">' . $formatValue($field, $values[0]) . '</span> ';
                $value = $values[1];
            } else {
                $value = $values;
            }
            echo '<i class="fas fa-arrow-right json_null"></i> <span class="json_string">' . $formatValue($field, $value) . '</span><br>';
        }
    }
}

