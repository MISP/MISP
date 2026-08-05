<?php
/**
 * Overmind theme layout.
 */

// Load the Overmind page registry in order to decide which asset stack to emit.
App::uses('OvermindPages', 'Tools');
App::uses('I18n', 'I18n');

$currentController = $this->params['controller'];
$currentAction = $this->params['action'];

$useBootstrap5 = OvermindPages::isMigrated($currentController, $currentAction);


// Overmind pages which own the whole viewport (no navbar, no footer, no header strip)
$isAuthPage  = $useBootstrap5 && OvermindPages::isAuthPage($currentController, $currentAction);


// Offset behavior for the legacy navbar 
$mainStyle = '';
if (!$useBootstrap5) {
    $debugBarShown = !empty($debugMode) && $debugMode !== 'debugOff';
    $mainStyle = ' style="padding-top:' . ($debugBarShown ? 0 : 50) . 'px;"';
}

// Conversion between ISO 639-2 code (`Config.language`) and BCP 47 tag (lang attribute) 
$htmlLang = 'en';
$configLanguage = (string)Configure::read('Config.language');
if ($configLanguage !== '') {
    if (strlen($configLanguage) === 3) {
        $mappedLanguage = I18n::getInstance()->l10n->map($configLanguage);
        $htmlLang = $mappedLanguage ?: 'en';
    } else {
        $htmlLang = str_replace('_', '-', $configLanguage);
    }
}


// Auto-logout feature : new event-driven check if MISP.disable_auto_logout is false
$autoLogoutEnabled = $useBootstrap5
    && !$isAuthPage
    && !empty($me)
    && !Configure::read('MISP.disable_auto_logout');

if (substr($currentAction, 0, 6) === 'admin_') {
    $here = $baseurl . '/admin/' . $currentController . '/'
        . substr($currentAction, 6);
} else {
    $here = $baseurl . '/' . $currentController . '/' . $currentAction;
}


?>



<!DOCTYPE html>
<html lang="<?= h($htmlLang) ?>">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="shortcut icon" href="<?= $baseurl ?>/img/faviconOvermind.png">
    <title><?= h($title_for_layout) .  ' - ' . h(Configure::read('MISP.title_text') ?: 'MISP') ?></title>
    <?php
        if ($useBootstrap5) {
            // Order matters: more specific stylesheets must come after more generic ones, so that they can override them.
            $css = [
                ['bootstrap5-custom.min', ['preload' => true]],
                ['tom-select.bootstrap5.min', ['preload' => true]],
                ['mainOvermind', ['preload' => true]],
                ['fontawesome7.min', ['preload' => true]],
                ['print', ['media' => 'print']],
                ['misp-iconify', ['preload' => true]],
            ];
            $js = [
                ['tom-select.complete.min', ['preload' => true]],
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
    <script>(function(){if(localStorage.getItem('darkMode')==='true'){document.documentElement.setAttribute('data-bs-theme','dark');}})()</script>
</head>
<body class="bg-light" data-controller="<?= h($currentController) ?>" data-action="<?= h($currentAction) ?>">
    <div class="main-wrapper">
        <!-- Navbar -->
        <header>
            <?php
                if (!$useBootstrap5) {
                    echo $this->element('global_menu');
                } elseif (!$isAuthPage) {
                    $context = [
                        'me' => $me ?? null,
                        'baseurl' => $baseurl,
                        'isAdmin' => $isAdmin ?? false,
                        'isSiteAdmin' => $isSiteAdmin ?? false,
                        'isAclSync' => $isAclSync ?? false,
                        'isAclRegexp' => $isAclRegexp ?? false,
                        'isAclAudit' => $isAclAudit ?? false,
                        'hostOrgUser' => $hostOrgUser ?? false,
                        'bookmarks' => $bookmarks ?? [],
                        'themes' => $themes ?? [],
                        'theme' => $theme ?? null,
                        'themesEnabled' => $themesEnabled ?? false,
                    ];
                    echo $this->element('navbar', [
                        'menus' => $this->Navbar->build($context),
                        'baseurl' => $baseurl,
                        'me' => $me ?? null,
                    ]);
                }
            ?>
        </header>
        <?php if ($useBootstrap5 && !$isAuthPage && Configure::read('debug') > 0): ?>
            <!-- Debug strip. mispOvermind.js moves Cake's .cake-error blocks
                 in here and badges the count. -->
            <div class="accordion mb-0" id="debugAccordionWrapper">
                <div class="accordion-item border-0">
                    <h2 class="accordion-header" id="debugHeading">
                        <button class="accordion-button collapsed bg-warning text-dark py-2"
                                style="border-radius: 0 !important; box-shadow: none !important;"
                                type="button"
                                data-bs-toggle="collapse"
                                data-bs-target="#debugCollapse"
                                aria-expanded="false"
                                aria-controls="debugCollapse">
                            <div class="d-flex justify-content-between align-items-center w-100 me-2">
                                <span>
                                    <i class="fas fa-bug me-2"></i>
                                    <?= __('Debug Mode Enabled') ?>
                                </span>
                                <span id="debugErrorBadge" class="badge bg-success ms-3">
                                    0 error
                                </span>
                            </div>
                        </button>
                    </h2>
                    <div id="debugCollapse"
                        class="accordion-collapse collapse"
                        aria-labelledby="debugHeading"
                        data-bs-parent="#debugAccordionWrapper">
                        <div id="debugAccordionContent"
                            class="accordion-body bg-dark text-light small"
                            style="max-height:500px; overflow:auto;">
                            <!-- Errors are injected here -->
                        </div>
                    </div>
                </div>
            </div>
        <?php endif; ?>
        <!-- Flash & Content -->
        <main role="main" class="content"<?= $mainStyle ?>>
            <div id="flashOverlay">
                <div id="flashContainer">
                    <?= $this->Flash->render(); ?>
                </div>
            </div>
            <div>
                <?php
                /*
                 * `hideHeaderSection` function is intended for pages where it is not necessary to print a title page
                 */
                if ($useBootstrap5 && !$isAuthPage && empty($hideHeaderSection)) {
                    echo $this->element('headerSection', [
                        'currentController' => $currentController,
                        'currentAction' => $currentAction,
                        'headerActions' => $headerActions ?? [],
                        'headerTitle' => $headerTitle ?? null,
                        'headerDescription' => $headerDescription ?? null,
                        'headerStats' => $headerStats ?? [],
                        'headerCount' => $headerCount ?? null,
                    ]);
                }
                ?>
                <?= $this->fetch('content') ?>
            </div>
        </main>
    </div>

    <!-- Footer -->
    <?php
        if (!$useBootstrap5) {
            echo $this->element('footer');
        } elseif (!$isAuthPage) {
            echo $this->element('footerBS5');
        }
    ?>

    <!-- Cake's query log, rendered only when debug is on -->
    <?= $this->element('sql_dump') ?>

    <!-- Modals, toasts, popovers and the loading overlay -->
    <?= $this->element('chrome_containers', ['legacy' => !$useBootstrap5]) ?>

    <!-- Additional JS for MISP -->
    <?php
        if ($useBootstrap5) {
            // Bootstrap 5 JS
            echo $this->element('genericElements/assetLoader', [
                'js' => [
                    'bootstrap.bundle.min',
                    'mispOvermind',
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
        var baseurl = <?= json_encode($baseurl, JSON_UNESCAPED_SLASHES) ?>;
        var here = <?= json_encode($here, JSON_UNESCAPED_SLASHES) ?>;

<?php if ($autoLogoutEnabled): ?>
        window.mispAutoLogout = true;
<?php endif; ?>

    </script>
</body>
</html>
