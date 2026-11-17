<?php
/*
 * An organisation column, drawn by Badges/organisation.
 *
 * Config:
 *   $field['data_path']        Hash path to the org (id, uuid, name)
 *   $field['default_org']      the name for a row with no org behind it
 *   $field['show_description'] the org's description under its name
 *   $field['org_title']        the name's tooltip, %s the org's name
 *   $field['fit']              the name never shrinks
 */
$org = Hash::extract($row, $field['data_path']);
if (empty($org)) {
    return;
}

$name = null;
if (empty($org['id']) && empty($org['uuid'])) {
    /*
     * Nothing to link to: a contained association with no row behind it
     * (a foreign key of 0, as on MISP's bundled galaxies), or
     * Organisation::GENERIC_MISP_ORGANISATION, whose id and uuid are '0'.
     */
    if (!empty($field['default_org'])) {
        $org = [];
        $name = $field['default_org'];
    } elseif (!empty($org['name'])) {
        $name = $org['name'];
    } elseif (!empty($org[0]) && is_string($org[0])) {
        $name = $org[0];
    }
    if ($name === null) {
        return;
    }
    $org = ['name' => $name];
}

$isCard = isset($viewMode) && $viewMode === 'card';
echo $this->element('genericElementsBS5/Badges/organisation', [
    'org' => $org,
    'orgTitle' => empty($field['org_title']) ? null : sprintf($field['org_title'], $org['name'] ?? ''),
    'orgFit' => !empty($field['fit']),
    'orgDescription' => empty($field['show_description']) ? false : ($isCard ? 'full' : 'line'),
]);
