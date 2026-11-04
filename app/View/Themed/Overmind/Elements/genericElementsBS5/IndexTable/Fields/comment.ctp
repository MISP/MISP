<?php
/*
 * A comment column: the comment at data_path, drawn as every comment is
 * (Badges/comment); `empty` stands in for a missing one, as in generic_field.
 */
$comment = Hash::get($row, $field['data_path']);
if ((!is_scalar($comment) || trim((string)$comment) === '') && !empty($field['empty'])) {
    echo '<span class="text-muted">' . h($field['empty']) . '</span>';
    return;
}
echo $this->element('genericElementsBS5/Badges/comment', [
    'comment' => is_scalar($comment) ? (string)$comment : '',
    'column' => true,
]);
