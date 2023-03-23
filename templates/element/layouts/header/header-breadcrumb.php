<?php

use Cake\Core\Configure;
use Cake\Routing\Router;

$controller = $this->request->getParam('controller');
$action = $this->request->getParam('action');
$curentPath = "{$controller}{$action}";
$entity = !empty($entity) ? $entity : [];

$breadcrumbLinks = '';
$breadcrumbAction = '';
$this->Breadcrumbs->setTemplates([
    'wrapper' => sprintf(
        '<nav class="header-breadcrumb d-lg-block d-none"{{attrs}}><ol class="">{{content}}</ol></nav>'
    ),
    'item' => '<li class="header-breadcrumb-item"{{attrs}}><i class="{{icon}} me-1"></i><a class="{{linkClass}}" href="{{url}}"{{innerAttrs}}>{{title}}</a></li>{{separator}}',
    'itemWithoutLink' => '<li class="header-breadcrumb-item"{{attrs}}><span{{innerAttrs}}>{{title}}</span></li>{{separator}}',
    'separator' => '<li class="header-breadcrumb-separator"{{attrs}}><span{{innerAttrs}}><i class="fa fa-sm fa-angle-right"></i></span></li>'
]);

if (!empty($breadcrumb)) {
    foreach ($breadcrumb as $i => $entry) {
        if (!empty($entry['textGetter'])) {
            if (is_array($entry['textGetter']) && !empty($entry['textGetter']['path'])) {
                $data = !empty(${$entry['textGetter']['varname']}) ? ${$entry['textGetter']['varname']} : $entity;
                $entry['label'] = Cake\Utility\Hash::get($data, $entry['textGetter']['path']);
            } else {
                $entry['label'] = Cake\Utility\Hash::get($entity, $entry['textGetter']);
            }
        }
        if (empty($entry['label'])) {
            $entry['label'] = "[{$entry['textGetter']}]";
        }
        if (!empty($entry['url_vars'])) {
            $entry['url'] = $this->DataFromPath->buildStringFromDataPath($entry['url'], $entity, $entry['url_vars']);
        }
        $this->Breadcrumbs->add(h($entry['label']), Router::url($entry['url']), [
            'title' => h($entry['label']),
            'templateVars' => [
                'linkClass' => $i == 0 ? 'fw-light' : '',
                'icon' => ($i == 0 && !empty($entry['icon'])) ? $this->FontAwesome->getClass(h($entry['icon'])) : ''
            ]
        ]);
    }
}

?>

<?php
echo $this->Breadcrumbs->render(
    [],
    ['separator' => '']
);

// $actionBar = '<div class="alert alert-primary">test</div>';
// $this->assign('actionBar', $actionBar);
?>

<?php $this->start('actionBar'); ?>
<?php // if (!empty($breadcrumbLinks) || !empty($breadcrumbAction)) : ?>
    <?php
        $lastCrumb = $breadcrumb[count($breadcrumb) - 1];
        echo $this->element('layouts/action-bar', [
            'links' => $lastCrumb['links'] ?? [],
            'actions' => $lastCrumb['actions'] ?? [],
            'route_path' => $lastCrumb['route_path'],
        ]);
    ?>
<?php // endif; ?>
<?php $this->end(); ?>