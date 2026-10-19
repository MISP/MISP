<?php
/**
 * The statistics page: one lazy tab per statistics_<page> fragment.
 *
 * $pages page => label, as the controller allows them; $page the one asked for
 */
$this->set('headerTitle', __('Statistics'));
$this->set('headerDescription', __('Usage of this instance and of its community.'));

echo $this->element('genericElements/assetLoader', [
    'css' => ['misp-matrix'],
    'js' => ['Chart.min', 'misp-matrix'],
]);

$tabs = [
    'data' => [
        'title' => __('Overview'),
        'icon' => 'fas fa-gauge-high',
        'description' => __('Data and community figures, with the daily activity of the last weeks.'),
    ],
    'orgs' => [
        'title' => __('Organisations'),
        'icon' => 'fas fa-building',
        'description' => __('The organisations residing on or known by this instance.'),
    ],
    'tags' => [
        'title' => __('Tags'),
        'icon' => 'misp-icon misp-icon-tag misp-simple',
        'description' => __('Event tags by taxonomy, and how many events carry each.'),
    ],
    'attributehistogram' => [
        'title' => __('Attribute types'),
        'icon' => 'misp-icon misp-icon-attribute misp-simple',
        'description' => __('The attribute types each organisation creates.'),
    ],
    'sightings' => [
        'title' => __('Sightings'),
        'icon' => 'misp-icon misp-icon-sighting misp-simple',
        'description' => __('The top sources of your organisation\'s sightings.'),
    ],
    'galaxyMatrix' => [
        'title' => __('Galaxy matrix'),
        'icon' => 'misp-icon misp-icon-galaxy misp-simple',
        'description' => __('How many events carry each technique of a matrix galaxy.'),
    ],
];
// The user and organisation counts are part of the overview here
$active = $page === 'users' ? 'data' : $page;

$layoutTabs = [];
foreach ($tabs as $key => $tab) {
    if (!isset($pages[$key])) {
        continue;
    }
    $layoutTabs[] = $tab + [
        'id' => $key,
        'active' => $key === $active,
        'left' => [['ajax' => $baseurl . '/users/statistics/' . $key]],
    ];
}

echo $this->element('genericElementsBS5/Layout/view_layout', [
    'data' => [],
    'tabs' => $layoutTabs,
]);
