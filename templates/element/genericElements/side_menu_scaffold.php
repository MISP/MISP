<?php
// return;
$children = '';
$backgroundColour = $darkMode ? 'bg-dark' : 'bg-light';
if (isset($menu[$metaGroup])) {
    foreach ($menu[$metaGroup] as $scope => $scopeData) {
        $children .= sprintf(
            '<a href="%s" class="fw-bold list-group-item list-group-item-action %s %s ps-1 border-0">%s</a>',
            empty($scopeData['url']) ? '#' : $baseurl . '/' . h($scopeData['url']),
            empty($scopeData['class']) ? '' : h($scopeData['class']),
            $backgroundColour,
            empty($scopeData['label']) ? h($scope) : $scopeData['label']
        );
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
            $active = ($scope === $this->request->getParam('controller') && $action === $this->request->getParam('action'));
            if (!empty($data['popup'])) {
                $link_template = '<a href="#" onClick="UI.submissionModalAutoGuess(\'%s\')" class="list-group-item list-group-item-action %s %s ps-3 border-0 %s">%s</a>';
            } else {
                $link_template = '<a href="%s" class="list-group-item list-group-item-action %s %s ps-3 border-0 %s">%s</a>';
            }
            $children .= sprintf(
                $link_template,
                empty($data['url']) ? '#' : $baseurl . h($data['url']),
                empty($data['class']) ? '' : h($data['class']),
                $active ? 'active' : '',
                $active ? '' : $backgroundColour,
                empty($data['label']) ? h($action) : $data['label']
            );
        }
    }
}
echo sprintf(
    '<div class="list-group %s h-100" id="side-menu-div">%s</div>',
    $backgroundColour,
    $children
);
