<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <?php echo $this->Html->charset(); ?>
    <meta name="viewport" content="width=device-width" />
    <title>
        <?php echo $title_for_layout, ' - '. h(Configure::read('MISP.title_text') ? Configure::read('MISP.title_text') : 'MISP'); ?>
    </title>
    <?php
        $css_collection = array(
            'bootstrap',
            //'bootstrap4',
            'bootstrap-datepicker',
            'bootstrap-colorpicker',
            'famfamfam-flags',
            'font-awesome',
            'jquery-ui',
            'chosen.min',
            'main',
            array('print', array('media' => 'print'))
        );
        if (Configure::read('MISP.custom_css')) {
            $css_collection[] = preg_replace('/\.css$/i', '', Configure::read('MISP.custom_css'));
        }
        $js_collection = array(
            'jquery',
            'misp-touch',
            'jquery-ui',
            'chosen.jquery.min'
        );
        echo $this->element('genericElements/assetLoader', array(
            'css' => $css_collection,
            'js' => $js_collection,
            'meta' => 'icon'
        ));
    ?>

</head>
<body>
    <div id="popover_form" class="ajax_popover_form"></div>
    <div id="popover_form_large" class="ajax_popover_form ajax_popover_form_large"></div>
    <div id="popover_form_x_large" class="ajax_popover_form ajax_popover_form_x_large"></div>
    <div id="popover_matrix" class="ajax_popover_form ajax_popover_matrix"></div>
    <div id="popover_box" class="popover_box"></div>
    <div id="screenshot_box" class="screenshot_box"></div>
    <div id="confirmation_box" class="confirmation_box"></div>
    <div id="gray_out" class="gray_out"></div>
    <div id="container">
        <?php
            echo $this->element('global_menu');
            $topPadding = '50';
            if (!empty($debugMode) && $debugMode != 'debugOff') {
                $topPadding = '0';
            }
        ?>
    </div>
    <div id="flashContainer" style="padding-top:<?php echo $topPadding; ?>px; !important;">
        <div id="main-view-container" class="container-fluid ">
            <?php
                echo $this->Flash->render();
            ?>
        </div>
    </div>
    <div>
        <?php
            echo $this->fetch('content');
        ?>
    </div>
    <?php
    echo $this->element('genericElements/assetLoader', array(
        'js' => array(
            'bootstrap',
            'bootstrap-timepicker',
            'bootstrap-datepicker',
            'bootstrap-colorpicker',
            'misp',
            'keyboard-shortcuts'
        )
    ));
    echo $this->element('footer');
    echo $this->element('sql_dump');
    ?>
    <div id = "ajax_success_container" class="ajax_container">
        <div id="ajax_success" class="ajax_result ajax_success"></div>
    </div>
    <div id = "ajax_fail_container" class="ajax_container">
        <div id="ajax_fail" class="ajax_result ajax_fail"></div>
    </div>
    <div class="loading">
        <div class="spinner"></div>
        <div class="loadingText"><?php echo __('Loading');?></div>
    </div>
    <script type="text/javascript">
    <?php
        if (!isset($debugMode)):
    ?>
        $(window).scroll(function(e) {
            $('.actions').css('left',-$(window).scrollLeft());
        });
    <?php
        endif;
    ?>
        var tabIsActive = true;
        var baseurl = '<?php echo $baseurl; ?>';
        var here = '<?php
                if (substr($this->params['action'], 0, 6) === 'admin_') {
                    echo $baseurl . '/admin/' . h($this->params['controller']) . '/' . h(substr($this->params['action'], 6));
                } else {
                    echo $baseurl . '/' . h($this->params['controller']) . '/' . h($this->params['action']);
                }
            ?>';
        $(document).ready(function(){
            $(window).blur(function() {
                tabIsActive = false;
            });
            $(window).focus(function() {
                tabIsActive = true;
            });
        <?php
            if (!Configure::read('MISP.disable_auto_logout') and $me):
        ?>
                checkIfLoggedIn();
        <?php
            endif;
        ?>
        if ($('.alert').text().indexOf("$flashErrorMessage") >= 0) {
            var flashMessageLink = '<span class="useCursorPointer underline bold" onClick="flashErrorPopover();">here</span>';
            $('.alert').html(($('.alert').html().replace("$flashErrorMessage", flashMessageLink)));
        }
        });
    </script>
</body>
</html>
