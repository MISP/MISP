<?php
/*
 * An organisation as the events index draws its creator org
 * (EventIndexHelper::orgCell()): its tile, its name and the reader's grade.
 *
 * Config:
 *   $field['data_path'] — Hash path to the org (id, uuid, name)
 *   $field['title']     — the name's tooltip, %s the org's name
 */
$org = Hash::get($row, $field['data_path'] ?? '');
if (empty($org['name'])) {
    echo '<span class="text-body-secondary">&mdash;</span>';
    return;
}
if (empty($this->viewVars['_orgCellAssets'])) {
    $this->viewVars['_orgCellAssets'] = true;
    echo $this->element('genericElements/assetLoader', ['css' => ['org-tile']]);
}
$ei = $this->EventIndex;
echo $ei->orgCell(
    $org,
    sprintf($field['title'] ?? '%s', $org['name']),
    $ei->grade(null, $org, $orgGrading ?? null),
    true
);
