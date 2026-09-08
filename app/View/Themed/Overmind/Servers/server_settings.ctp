<?php
/**
 * The page itself only renders the health cards and the tab bar; the content
 * of every tab is pulled over ajax from this same action
 * (ServersController::serverSettings), which returns the bare fragment
 * `Servers/ajax/server_settings_tab` for an XHR.
 */

App::uses('ServerSettingGroups', 'Tools');

$this->set('headerTitle', __('Server Settings & Maintenance'));
$this->set('headerDescription', __('Review and tune the configuration of this instance.'));
$this->set('headerCountText', '');

$viewTabs = array();

foreach (ServerSettingGroups::tabs() as $section) {
    if ($section['tab'] === 'files' && !empty(Configure::read('Security.disable_instance_file_uploads'))) {
        continue;
    }
    if ($section['tab'] === 'workers' && empty($worker_array)) {
        continue;
    }

    $viewTab = array(
        'id' => strtolower($section['tab']),
        'title' => $section['title'],
        'icon' => $section['icon'],
        'count' => empty($tabs[$section['tab']]['errors']) ? null : $tabs[$section['tab']]['errors'],
    );

    $viewTab['active'] = $tab === $section['tab'];
    $viewTab['left'] = array(
        array('ajax' => $baseurl . '/servers/serverSettings/' . $section['tab']),
    );

    $viewTabs[] = $viewTab;
}

$this->set('headerActions', array(
    array(
        'type' => 'navigate',
        'url' => $baseurl . '/servers/serverSettings/download',
        'icon' => 'download',
        'label' => __('Download report'),
    ),
));
?>

<?php if ($writeableFiles[APP . 'Config/config.php'] != 0 && !Configure::read('MISP.system_setting_db')): ?>
    <div class="container-fluid">
        <div class="alert alert-danger d-flex align-items-center gap-2" role="alert">
            <i class="fas fa-triangle-exclamation"></i>
            <?= __('Warning: app/Config/config.php is not writeable. This means that any setting changes made here will NOT be saved.') ?>
        </div>
    </div>
<?php endif; ?>

<?= $this->element('healthElementsBS5/health_cards', array(
    'issues' => $issues,
    'diagnostic_errors' => $diagnostic_errors,
)) ?>

<?= $this->element('genericElementsBS5/Layout/view_layout', array(
    'data' => array(),
    'tabs' => $viewTabs,
)) ?>
