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

    $lastCrumb = $breadcrumb[count($breadcrumb) - 1];

    if (!empty($lastCrumb['links'])) {
        // dd($lastCrumb['links']);
        foreach ($lastCrumb['links'] as $i => $linkEntry) {
            if (empty($linkEntry['route_path'])) {
                $active = false;
            } else {
                $active = $linkEntry['route_path'] == $lastCrumb['route_path'];
            }
            if (!empty($linkEntry['url_vars'])) {
                $linkEntry['url'] = $this->DataFromPath->buildStringFromDataPath($linkEntry['url'], $entity, $linkEntry['url_vars']);
            }
            if (!empty($linkEntry['selfLink'])) {
                $url = Router::url(null);
            } else {
                $url = Router::url($linkEntry['url']);
            }
            $breadcrumbLinks .= sprintf(
                '<a class="btn btn-%s btn-sm text-nowrap" role="button" href="%s">%s</a>',
                $active ? 'secondary' : 'outline-secondary',
                $url,
                h($linkEntry['label'])
            );
        }
    }
    $badgeNumber = 0;
    if (!empty($lastCrumb['actions'])) {
        foreach ($lastCrumb['actions'] as $i => $actionEntry) {
            if (!empty($actionEntry['url_vars'])) {
                $actionEntry['url'] = $this->DataFromPath->buildStringFromDataPath($actionEntry['url'], $entity, $actionEntry['url_vars']);
            }
            if (!empty($actionEntry['badge'])) {
                $badgeNumber += 1;
            }
            $breadcrumbAction .= sprintf(
                '<a class="dropdown-item %s" href="#" onclick="%s"><i class="me-1 %s"></i>%s%s</a>',
                !empty($actionEntry['variant']) ? sprintf('dropdown-item-%s', $actionEntry['variant']) : '',
                sprintf('UI.overlayUntilResolve(this, UI.submissionModalAutoGuess(\'%s\'))', h(Router::url($actionEntry['url']))),
                !empty($actionEntry['icon']) ? $this->FontAwesome->getClass(h($actionEntry['icon'])) : '',
                h($actionEntry['label']),
                !empty($actionEntry['badge']) ? $this->Bootstrap->badge($actionEntry['badge']) : ''
            );
        }
    }
}

?>

<?php
echo $this->Breadcrumbs->render(
    [],
    ['separator' => '']
);
?>

<?php if (!empty($breadcrumbLinks) || !empty($breadcrumbAction)) : ?>
    <div class="breadcrumb-link-container position-absolute end-0 d-flex">
        <div class="header-breadcrumb-children d-none d-md-flex btn-group">
            <?= $breadcrumbLinks ?>
            <?php if (!empty($breadcrumbAction)) : ?>
                <a class="btn btn-primary btn-sm dropdown-toggle" href="#" role="button" id="dropdownMenuBreadcrumbAction" data-bs-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                    <?= __('Actions') ?>
                    <?=
                        $badgeNumber == 0 ? '' : $this->Bootstrap->badge([
                            'text' => h($badgeNumber),
                            'variant' => 'warning',
                            'pill' => false,
                            'title' => __n('There is {0} action available', 'There are {0} actions available', $badgeNumber, h($badgeNumber)),
                        ])
                    ?>
                </a>
                <div class="dropdown-menu dropdown-menu-end" aria-labelledby="dropdownMenuBreadcrumbAction">
                    <?= $breadcrumbAction ?>
                </div>
            <?php endif; ?>
        </div>
    </div>
<?php endif; ?>