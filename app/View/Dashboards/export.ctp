<?php
    $data = array(
        'title' => __('Export Dashboard Settings'),
        'content' => array(
            array(
                'paragraph' => __('Simply copy and share your dashboard settings below. Make sure that you sanitise it so that you do not share anything sensitive. Simply click on the JSON below to select it.')
            ),
            array(
                'title' => __('Dashboard settings'),
                'code' => json_encode($data, JSON_PRETTY_PRINT)
            )
        )
    );
    echo $this->element('genericElements/infoModal', array('data' => $data));
?>
