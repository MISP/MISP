<?php
/**
 * Content of one Server Settings tab, served as a bare fragment to the ajax
 * tab container of `Servers/server_settings.ctp`.
 *
 * Settings tabs are laid out in sections by ServerSettingGroups; the tabs that
 * are not lists of settings get their own renderer.
 */

App::uses('ServerSettingGroups', 'Tools');

if ($tab === 'workers') {
    echo $this->element('healthElementsBS5/workers', array(
        'worker_array' => $worker_array,
    ));
} elseif ($tab === 'diagnostics') {
    echo $this->element('healthElementsBS5/diagnostics');
} elseif ($tab === 'files') {
    echo $this->element('healthElementsBS5/files', array(
        'files' => $files,
    ));
} elseif ($tab === 'correlations') {
    echo $this->element('healthElementsBS5/correlations', array(
        'correlation_metrics' => $correlation_metrics,
    ));
} elseif (ServerSettingGroups::hasGroups($tab)) {
    // $finalSettings arrives grouped by subGroup; the section layout regroups the flat list itself.
    $flatSettings = array();
    foreach ($finalSettings as $subGroupSettings) {
        foreach ($subGroupSettings as $setting) {
            $flatSettings[] = $setting;
        }
    }

    echo $this->element('healthElementsBS5/settings_sections', array(
        'tab' => $tab,
        'sections' => ServerSettingGroups::split($tab, $flatSettings),
    ));
}
