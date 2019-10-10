<?php
    echo '<td class="short action-links">';
    foreach ($actions as $action) {
        $url_param_data_paths = '';
        $url = empty($action['url']) ? '#' : h($action['url']);
        if (!empty($action['url_params_data_paths'])) {
            if (is_array($action['url_params_data_paths'])) {
                $temp = array();
                foreach ($action['url_params_data_paths'] as $path) {
                    $temp[] = h(Hash::extract($row, $path)[0]);
                }
                $url_param_data_paths = implode('/', $temp);
            } else {
                $url_param_data_paths = h(Hash::extract($row, $action['url_params_data_paths'])[0]);
            }
            $url .= '/' . $url_param_data_paths;
        }
        if (isset($action['postLink'])) {
            echo $this->Form->postLink(
                '',
                $url,
                array(
                    'class' => $this->FontAwesome->getClass($action['icon']) . ' black ' . (empty($action['class']) ? '' : h($action['class'])),
                    'title' => empty($action['title']) ? '' : h($action['title']),
                    'aria-label' => empty($action['aria-label']) ? '' : h($action['aria-label']),
                ),
                empty($action['postLinkConfirm'])? '' : $action['postLinkConfirm']
            );
        } else {
            echo sprintf(
                '<a href="%s" title="%s" aria-label="%s" %s><i class="black %s"></i></a> ',
                $url,
                empty($action['title']) ? '' : h($action['title']),
                empty($action['title']) ? '' : h($action['title']),
                empty($action['onclick']) ? '' : sprintf('onclick="%s"', $action['onclick']),
                $this->FontAwesome->getClass($action['icon'])
            );
        }
    }
    echo '</td>';
?>
