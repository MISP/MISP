<?php
$children = '';
if (isset($menu[$metaGroup])) {
    foreach ($menu[$metaGroup] as $scope => $scopeData) {
        foreach ($scopeData['children'] as $action => $data) {
            if (
                (!empty($data['requirements']) && !$data['requirements']) ||
                (
                    !empty($data['actions']) &&
                    !in_array($this->request->getParam('action'), $data['actions'])
                ) ||
                !empty($data['actions']) && $scope !== $this->request->getParam('controller')
            ) {
                continue;
            }
            $matches = [];
            preg_match_all('/\{\{.*?\}\}/', $data['url'], $matches);
            if (!empty($matches[0])) {
                $mainEntity = \Cake\Utility\Inflector::underscore(\Cake\Utility\Inflector::singularize($scope));
                foreach ($matches as $match) {
                    $data['url'] = str_replace(
                        $match[0],
                        Cake\Utility\Hash::extract($entity, trim($match[0], '{}'))[0],
                        $data['url']
                    );
                }
            }
            $children .= sprintf(
                '<a class="dropdown-item" href="%s">%s</a>',
                empty($data['url']) ? '#' : $baseurl . h($data['url']),
                empty($data['label']) ? h($action) : $data['label']
            );
        }
    }
}
echo sprintf(
    '<div class="dropdown show">%s%s</div>',
    sprintf(
        '<a class="btn btn-secondary dropdown-toggle" href="#" role="button" id="sideMenuDropdownLink" data-bs-toggle="dropdown" aria-haspopup="true" aria-expanded="false">%s</a>',
        __('Navigation')
    ),
    sprintf(
        '<div class="dropdown-menu" aria-labelledby="sideMenuDropdownLink">%s</div>',
        $children
    )
);
