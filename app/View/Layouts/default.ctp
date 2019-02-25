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
        echo $this->Html->meta('icon');
        echo $this->Html->css('bootstrap');
        //echo $this->Html->css('bootstrap4');
        echo $this->Html->css('bootstrap-datepicker');
        echo $this->Html->css('bootstrap-timepicker');
        echo $this->Html->css('bootstrap-colorpicker');
        echo $this->Html->css('famfamfam-flags');
        echo $this->Html->css('font-awesome');
        if ($me) {
            echo $this->Html->css('main.css?' . $queryVersion);
        } else {
            echo $this->Html->css('main');
        }
        if (Configure::read('MISP.custom_css')) {
            $css = preg_replace('/\.css$/i', '', Configure::read('MISP.custom_css'));
            echo $this->Html->css($css);
        }
        echo $this->Html->css('print', 'stylesheet', array('media' => 'print'));
        echo $this->Html->css('jquery-ui');
        echo $this->Html->script('jquery'); // Include jQuery library
        echo $this->Html->script('misp-touch'); // touch interface support
        echo $this->Html->script('jquery-ui'); // UI support
        echo $this->Html->css('chosen.min');
        echo $this->Html->script('chosen.jquery.min');
    ?>

</head>
<body>
    <div id="popover_form" class="ajax_popover_form"></div>
    <div id="popover_form_large" class="ajax_popover_form ajax_popover_form_large"></div>
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
                $flash = $this->Flash->render();
                echo $flash;
            ?>
        </div>
    </div>
    <div>
        <?php
            echo $this->fetch('content');
        ?>
    </div>
    <?php
    echo $this->element('footer');
    echo $this->element('sql_dump');
    echo $this->Html->script('bootstrap');
    //echo $this->Html->script('bootstrap4');
    echo $this->Html->script('bootstrap-timepicker');
    echo $this->Html->script('bootstrap-datepicker');
    echo $this->Html->script('bootstrap-colorpicker');
    if ($me) {
        echo $this->Html->script('misp.js?' . $queryVersion);
        echo $this->Html->script('keyboard-shortcuts.js?' . $queryVersion);
    }
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
                    echo $baseurl . '/admin/' . $this->params['controller'] . '/' . substr($this->params['action'], 6);
                } else {
                    echo $baseurl . '/' . $this->params['controller'] . '/' . $this->params['action'];
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
            //$('#flashErrorMessage').html()
            var flashMessageLink = '<span class="useCursorPointer underline bold" onClick="flashErrorPopover();">here</span>';
            $('.alert').html(($('.alert').html().replace("$flashErrorMessage", flashMessageLink)));
        }
        });
    </script>
</body>
</html>
