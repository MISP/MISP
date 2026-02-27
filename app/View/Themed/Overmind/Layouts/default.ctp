<!DOCTYPE html>
<html lang="<?= Configure::read('Config.language') === 'eng' ? 'en' : Configure::read('Config.language') ?>">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="shortcut icon" href="<?= $baseurl ?>/img/favicon.png">
    <title><?= h($title_for_layout) .  ' - ' . h(Configure::read('MISP.title_text') ?: 'MISP') ?></title>
    <?php
        $bootstrap5Pages = [
            ['controller' => 'users', 'action' => 'login'],
            ['controller' => 'noticelists', 'action' => 'index'],
            ['controller' => 'events', 'action' => 'index'],
        ];

        $currentController = $this->params['controller'];
        $currentAction = $this->params['action'];

        $useBootstrap5 = false;

        foreach ($bootstrap5Pages as $page) {
            if (
                $currentController === $page['controller'] &&
                $currentAction === $page['action']
            ) {
                $useBootstrap5 = true;
                break;
            }
        }

        if ($useBootstrap5) {
            $css = [
                ['bootstrap5-custom.min', ['preload' => true]],
                ['mainOvermind', ['preload' => true]],
                ['fontawesome7.min', ['preload' => true]],
                ['print', ['media' => 'print']],
            ];
            $js = [
                ['jquery', ['preload' => true]],
                ['chosen.jquery.min', ['preload' => true]]
            ];
        } else {
            $css = [
                ['bootstrap', ['preload' => true]],
                ['main', ['preload' => true]],
                ['bootstrap-datepicker', ['preload' => true]],
                ['bootstrap-colorpicker', ['preload' => true]],
                ['font-awesome', ['preload' => true]],
                ['chosen.min', ['preload' => true]],
                ['print', ['media' => 'print']],
            ];
            $js = [
                ['jquery', ['preload' => true]],
                ['chosen.jquery.min', ['preload' => true]],
        ];
        }
        if (Configure::read('MISP.custom_css')) {
            $css[] = preg_replace('/\.css$/i', '', Configure::read('MISP.custom_css'));
        }
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
    <div class="main-wrapper">
        <!-- Navbar -->
        <header>
            <?php
                if ($useBootstrap5){
                    // Don't print the navbar for the login page
                    if (!($currentController === 'users' && $currentAction === 'login')) {
                        $context = [
                            'me' => $me,
                            'baseurl' => $baseurl,
                            'isAdmin' => $isAdmin,
                            'isSiteAdmin' => $isSiteAdmin,
                            'isAclSync' => $isAclSync,
                            'isAclRegexp' => $isAclRegexp,
                            'isAclAudit' => $isAclAudit,
                            'hostOrgUser' => $hostOrgUser,
                            'bookmarks' => $bookmarks,
                            'themes' => $themes,
                        ];
                        $menus = $this->Navbar->build($context);
                        echo $this->element('navbar', [
                            'menus' => $menus,
                            'baseurl' => $baseurl,
                            'me' => $me ?? null
                        ]);
                    }
                    $topPadding = '0';
                }
                else {
                    echo $this->element('global_menu');
                    $topPadding = '50';
                    if (!empty($debugMode) && $debugMode != 'debugOff') {
                        $topPadding = '0';
                    }
                }
            ?>
        </header> 
        <!-- Flash & Content -->
        <main role="main" class="content">
            <div id="flashOverlay">
                <div id="flashContainer">
                    <?= $this->Flash->render(); ?>
                </div>
            </div>
            <div>
                <?php
                if ($useBootstrap5 && !($currentController === 'users' && $currentAction === 'login') && !empty($title_for_layout)) {
                    echo $this->element('headerSection', [
                        'pageTitle' => $title_for_layout,
                        'headerActions' => $headerActions ?? []
                    ]);
                }
                ?>
                <?= $this->fetch('content') ?>
            </div>
        </main>
    </div>


    <!-- TO DO Footer & SQL dump -->
    <?php
        if ($useBootstrap5){
            // Don't print the footer for the login page
            if (!($currentController === 'users' && $currentAction === 'login')) {
                echo $this->element('footerBS5'); 
            }
        }
        else {
            echo $this->element('footer');
        }
    ?>
    <?= $this->element('sql_dump') ?>

    <!-- Modals, Toasts and Popovers -->
    <div id="popover_form" class="ajax_popover_form"></div>
    <div id="popover_form_large" class="ajax_popover_form ajax_popover_form_large"></div>
    <div id="popover_form_x_large" class="ajax_popover_form ajax_popover_form_x_large"></div>
    <div id="popover_matrix" class="ajax_popover_form ajax_popover_matrix"></div>
    <div id="popover_box" class="popover_box"></div>
    <div id="confirmation_box"></div>
    <div id="gray_out"></div>
    <div id="mainModal" class="modal fade" tabindex="-1" role="dialog" aria-hidden="true"></div>
    <div id="mainToastContainer" class="main-toast-container"></div>
    <div id="mainModalContainer"></div>


    <!-- Ajax Results -->
    <div id="ajax_success_container" class="ajax_container">
        <div id="ajax_success" class="ajax_result ajax_success"></div>
    </div>
    <div id="ajax_fail_container" class="ajax_container">
        <div id="ajax_fail" class="ajax_result ajax_fail"></div>
    </div>


     <!-- Loading -->
    <div class="loading">
        <div class="spinner"></div>
        <div class="loadingText"><?= __('Loading'); ?></div>
    </div>


    <!-- Additional JS for MISP -->
    <?php
        if ($useBootstrap5) {
            // Bootstrap 5 JS 
            echo $this->element('genericElements/assetLoader', [
                'js' => [
                    'misp-touch',
                    'bootstrap.bundle.min',
                    'misp',
                    'keyboard-shortcuts-definition',
                    'keyboard-shortcuts',
                ],
            ]);
        } else {
            // Bootstrap 2 JS
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
        }
    ?>

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

        $(document).on('click', '.ajax-toggle, .ajax-call', function(e) {
            e.preventDefault();

            var url = $(this).data('url');
            var $row = $(this).closest('tr');

            $.ajax({
                type: "get",
                url: url,
                success: function(data) {

                    var $temp = $('<div>').html(data);
                    var $form = $temp.find('form');

                    if ($form.length) {
                        $.post($form.attr('action'), $form.serialize(), function() {
                            showMessage('success', 'Field updated.');
                            location.reload();
                        });
                    } else {
                        showMessage('success', 'Action executed.');
                        location.reload();
                    }
                },
                error: function() {
                    showMessage('fail', 'Action failed.');
                }
            });
        });


        $(document).ready(function () {
            var $flash = $('#flashContainer');

            if ($flash.children().length > 0) {
                setTimeout(function () {
                    $flash.addClass('fade-out');

                    setTimeout(function () {
                        $flash.remove();
                    }, 600); // correspond à la durée de transition
                }, 10000); // 10 secondes
            }
        });
    </script>
</body>
</html>
