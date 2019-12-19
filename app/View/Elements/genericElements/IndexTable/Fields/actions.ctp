<?php
    /*
     *  Create the action field in a table
     *  - pass a list of actions that will be added as separate icons to the field
     *  - each action can have the following fields setTLDs
     *    - url: url to query
     *    - url_params_data_paths: add dynamic URL elements such as an id to the URL. Can be an array with each value added in a separate param
     *    - title: title of the action. Automatically generates aria labels too
     *    - postLink: convert the button into a POST request
     *    - postLinkConfirm: As the user to confirm the POST before submission with the given message
     *    - onClick: custom onClick action instead of a simple GET/POST request
     *    - icon: FA icon (added using the helper, knowing the fa domain is not needed, just add the short name such as "edit")
     *  - requirement evaluates to true/false
     *  - complex_requirement - add complex requirements via lambda functions:
     *    - function: the lambda function
     *    - options: array of options
     */
    echo '<td class="short action-links">';
    foreach ($actions as $action) {
        if (isset($action['requirement']) && !$action['requirement']) {
            continue;
        }
        if (isset(
            $action['complex_requirement']) &&
            !$action['complex_requirement']['function']($row, $action['complex_requirement']['options'])
        ) {
            continue;
        }
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
