<?php
    $data_path = Hash::extract($data, $field['path']);
    $result = [];
    foreach ($data_path as $key => $ip) {
        $data_ip['ip'] = $ip; 
        $action = ['class' => 'modal-open',
                    'url' => $baseurl. "/authKeys/pin/" . h($data['AuthKey']['id']) . '/' . h($ip),
                    'icon' => 'thumbtack',
                    'postLink' => true,
                    'postLinkConfirm' => __('Use this as only possible source IP?'),
                    'title' => __('Use this IP')];  
        $form = $this->Form->postLink(
            '',
            $action['url'],
            array(
                'class' => $this->FontAwesome->getClass($action['icon']) . ' ' . (empty($action['class']) ? '' : h($action['class'])),
                'title' => empty($action['title']) ? '' : h($action['title']),
                'aria-label' => empty($action['title']) ? '' : h($action['title']),
            ),
            $action['postLinkConfirm']
        ) . ' ';
        $result[$key] = h($ip) . " " . $form;
    }
    
    $result = implode('<br />', $result);
    echo $result;
?>
