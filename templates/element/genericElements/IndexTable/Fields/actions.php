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
     *    - onclick: custom onclick action instead of a simple GET/POST request
     *    - onclick_params_data_path: pass a data path param to the onclick field. requires [onclick_params_data_path] in the onclick field
     *      as a needle for replacement
     *    - icon: FA icon (added using the helper, knowing the fa domain is not needed, just add the short name such as "edit")
     *  - requirement evaluates to true/false
     *  - complex_requirement - add complex requirements via lambda functions:
     *    - function($row, $options): the lambda function. $row contain the row data
     *    - options: array of options. datapaths described in the datapath keyname will be extracted and replaced with the actual row value
    */
    echo '<td class="action-links text-end text-nowrap">';
    echo '<span class="btn-group">';
    foreach ($actions as $action) {
        if (isset($action['requirement']) && !$action['requirement']) {
            continue;
        }
        if (isset($action['complex_requirement'])) {
            if ($action['complex_requirement'] instanceof Closure) {
                $requirementMet = $action['complex_requirement']($row);
            } else {
                if (isset($action['complex_requirement']['options']['datapath'])) {
                    foreach ($action['complex_requirement']['options']['datapath'] as $name => $path) {
                        $action['complex_requirement']['options']['datapath'][$name] = empty($this->Hash->extract($row, $path)[0]) ? null : $this->Hash->extract($row, $path)[0];
                    }
                }
                $options = isset($action['complex_requirement']['options']) ? $action['complex_requirement']['options'] : array();
                $requirementMet = $action['complex_requirement']['function']($row, $options);
                if (!$requirementMet) {
                    continue;
                }
            }
        }
        $url_param_data_paths = '';
        $url = empty($action['url']) ? '#' : $baseurl . h($action['url']);
        if (!empty($action['url_params_data_paths'])) {
            if (is_array($action['url_params_data_paths'])) {
                $temp = array();
                foreach ($action['url_params_data_paths'] as $path) {
                    $temp[] = h(Cake\Utility\Hash::extract($row, $path)[0]);
                }
                $url_param_data_paths = implode('/', $temp);
            } else {
                $url_param_data_paths = h(Cake\Utility\Hash::extract($row, $action['url_params_data_paths'])[0]);
            }
            $url .= '/' . $url_param_data_paths;
        }
        if (!empty($action['url_named_params_data_paths'])) {
            if (is_array($action['url_named_params_data_paths'])) {
                $temp = array();
                foreach ($action['url_named_params_data_paths'] as $namedParam => $path) {
                    $temp[] = sprintf('%s:%s', h($namedParam), h($this->Hash->extract($row, $path)[0]));
                }
                $url_param_data_paths = implode('/', $temp);
            }
            $url .= '/' . $url_param_data_paths;
        }
        if (!empty($action['url_extension'])) {
            $url .= '.' . $action['url_extension'];
        }
        if (isset($action['postLink'])) {
            echo $this->Form->postLink(
                '',
                $url,
                array(
                    'class' => $this->FontAwesome->getClass($action['icon']) . (empty($action['class']) ? '' : h($action['class'])),
                    'title' => empty($action['title']) ? '' : h($action['title']),
                    'aria-label' => empty($action['aria-label']) ? '' : h($action['aria-label']),
                ),
                empty($action['postLinkConfirm'])? '' : $action['postLinkConfirm']
            );
        } else {
            if (!empty($action['onclick']) && !empty($action['onclick_params_data_path'])) {
                $action['onclick'] = str_replace(
                    '[onclick_params_data_path]',
                    h(Cake\Utility\Hash::extract($row, $action['onclick_params_data_path'])[0]),
                    $action['onclick']
                );

            } else if (!empty($action['open_modal']) && !empty($action['modal_params_data_path'])) {
                if (is_array($action['modal_params_data_path'])) {
                    foreach ($action['modal_params_data_path'] as $k => $v) {
                        $modal_url = str_replace(
                            sprintf('{{%s}}', $k),
                            h(Cake\Utility\Hash::extract($row, $v)[0]),
                            $action['open_modal']
                        );
                    }
                } else {
                    $modal_url = str_replace(
                        '[onclick_params_data_path]',
                        h(Cake\Utility\Hash::extract($row, $action['modal_params_data_path'])[0]),
                        $action['open_modal']
                    );
                }
                $reload_url = !empty($action['reload_url']) ? $action['reload_url'] : $this->Url->build(['action' => 'index']);
                $action['onclick'] = sprintf('UI.submissionModalForIndex(\'%s\', \'%s\', \'%s\')', h($modal_url), h($reload_url), h($tableRandomValue));
            }
            echo sprintf(
                '<a href="%s" title="%s" aria-label="%s" %s %s class="btn btn-sm btn-%s table-link-action"><i class="%s"></i></a> ',
                $url,
                empty($action['title']) ? '' : h($action['title']),
                empty($action['title']) ? '' : h($action['title']),
                empty($action['dbclickAction']) ? '' : 'class="dblclickActionElement"',
                empty($action['onclick']) ? '' : sprintf('onClick="%s"', $action['onclick']),
                empty($action['variant']) ? 'outline-text' : h($action['variant']),
                $this->FontAwesome->getClass($action['icon'])
            );
        }
    }
    echo '</span>';
    echo '</td>';
?>
