<?php
App::uses('AnalystData', 'Model');
/*
 * The object an analyst data row points at (AnalystData/target_ref). Shared by
 * the Analyst Data indexes for the parent "Target" and the "Related object".
 *
 * Config:
 *   $field['type_path']   — Hash path to the object type (e.g. 'Note.object_type')
 *   $field['uuid_path']   — Hash path to the object uuid (e.g. 'Note.object_uuid')
 *   $field['sha256_path'] — Hash path to the SHA-256 naming a value target
 *
 * $analystTargets (address => description), set by the controller from
 * AnalystData::describeTargets(), holds the targets the user can open.
 */
$type = (string)Hash::get($row, $field['type_path'] ?? '');
$isValue = in_array($type, AnalystData::SHA256_TARGETS, true);
$address = (string)Hash::get($row, $field[$isValue ? 'sha256_path' : 'uuid_path'] ?? '');

echo $this->element('AnalystData/target_ref', [
    'type' => $type,
    'address' => $address,
    'target' => $analystTargets[$isValue ? strtolower($address) : $address] ?? null,
]);
