<!DOCTYPE html>
<html lang="<?= Configure::read('Config.language') === 'eng' ? 'en' : Configure::read('Config.language') ?>">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width">
    <link rel="shortcut icon" href="<?= $baseurl ?>/img/favicon.png">
    <title><?= h($title_for_layout), ' - ', h(Configure::read('MISP.title_text') ?: 'MISP') ?></title>
    <?php
        $css = [
            ['bootstrap', ['preload' => true]],
            ['bootstrap-datepicker', ['preload' => true]],
            ['bootstrap-colorpicker', ['preload' => true]],
            ['font-awesome', ['preload' => true]],
            ['chosen.min', ['preload' => true]],
            ['main', ['preload' => true]],
            ['print', ['media' => 'print']],
        ];
        if (Configure::read('MISP.custom_css')) {
            $css[] = preg_replace('/\.css$/i', '', Configure::read('MISP.custom_css'));
        }
        $js = [
            ['jquery', ['preload' => true]],
            ['chosen.jquery.min', ['preload' => true]],
        ];
        if (!empty($additionalCss)) {
            $css = array_merge($css, $additionalCss);
        }
        if (!empty($additionalJs)) {
            $js = array_merge($js, $additionalJs);
        }
        echo $this->element('genericElements/assetLoader', [
            'css' => $css,
            'js' => $js,
        ]);
    ?>
</head>
<body data-controller="<?= h($this->params['controller']) ?>" data-action="<?= h($this->params['action']) ?>">
    <div id="popover_form" class="ajax_popover_form"></div>
    <div id="popover_form_large" class="ajax_popover_form ajax_popover_form_large"></div>
    <div id="popover_form_x_large" class="ajax_popover_form ajax_popover_form_x_large"></div>
    <div id="popover_matrix" class="ajax_popover_form ajax_popover_matrix"></div>
    <div id="popover_box" class="popover_box"></div>
    <div id="confirmation_box"></div>
    <div id="gray_out"></div>
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
        <div id="main-view-container" class="container-fluid">
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
    echo $this->element('genericElements/assetLoader', [
        'js' => [
            'misp-touch',
            'bootstrap',
            'bootstrap-timepicker',
            'bootstrap-datepicker',
            'bootstrap-colorpicker',
            'misp',
            'keyboard-shortcuts-definition',
            'keyboard-shortcuts',
        ],
    ]);
    echo $this->element('footer');
    echo $this->element('sql_dump');
    ?>
    <div id="ajax_success_container" class="ajax_container">
        <div id="ajax_success" class="ajax_result ajax_success"></div>
    </div>
    <div id="ajax_fail_container" class="ajax_container">
        <div id="ajax_fail" class="ajax_result ajax_fail"></div>
    </div>
    <div class="loading">
        <div class="spinner"></div>
        <div class="loadingText"><?php echo __('Loading');?></div>
    </div>
    <script>
    <?php
        if (!isset($debugMode)):
    ?>
        $(window).scroll(function() {
            $('.actions').css('left',-$(window).scrollLeft());
        });
    <?php
        endif;
    ?>
        var baseurl = '<?php echo $baseurl; ?>';
        var here = '<?php
                if (substr($this->params['action'], 0, 6) === 'admin_') {
                    echo $baseurl . '/admin/' . h($this->params['controller']) . '/' . h(substr($this->params['action'], 6));
                } else {
                    echo $baseurl . '/' . h($this->params['controller']) . '/' . h($this->params['action']);
                }
            ?>';
        <?php
            if (!Configure::read('MISP.disable_auto_logout') && isset($me) && $me):
        ?>
                //checkIfLoggedIn();
        <?php
            endif;
        ?>
    </script>
</body>
</html>
