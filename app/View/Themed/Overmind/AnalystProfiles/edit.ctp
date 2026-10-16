<?php
/**
 * The workbench: seven sections, one open, and the value under
 * assessment beside them.
 *
 * @var array $profile
 * @var bool $editable
 * @var array $bench
 */
echo $this->element('genericElements/assetLoader', array(
    'css' => array('value-palette', 'analyst-profile'),
    'js' => array('analyst-profile', 'analyst-profile-help'),
));

$focus = $bench['focus'];
$query = $focus === null
    ? array()
    : array('value' => $focus);

$this->set('headerTitle', $profile['name']);
$this->set('headerBreadcrumb', array(
    array('label' => __('Analyst Profiles'),
        'url' => array('action' => 'index')),
    $profile['name'],
));
$this->set('headerCountText', sprintf(__('rev %s'), $profile['revision']));
$this->set('headerCount', $profile['revision']);
$this->set('headerDescription', __('Your copy of the scoring rules.'
    . ' Edit a section on the left; the value on the right is rescored'
    . ' as you go.'));
$this->set('headerActions', array(
    array(
        'type' => 'navigate',
        'label' => __('Open the full comparison'),
        'icon' => 'up-right-and-down-left-from-center',
        'url' => $this->Html->url(array(
            'action' => 'simulate', $profile['id'], '?' => $query)),
    ),
    array(
        'type' => 'navigate',
        'label' => __('Export'),
        'icon' => 'file-export',
        'url' => $this->Html->url(array('action' => 'export', $profile['id'])),
    ),
    array(
        'type' => 'modal',
        'label' => __('Save'),
        'icon' => 'save',
        'url' => '#',
        'onClick' => 'analystProfileSave',
    ),
));
$this->set('headerActionGroups', array('navigate' => array('mode' => 'none')));

echo $this->element('AnalystProfiles/workbench');
