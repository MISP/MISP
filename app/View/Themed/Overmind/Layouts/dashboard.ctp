<?php
/**
 * Overmind themed override of Layouts/dashboard.ctp (DD-08).
 *
 * Cake's Themed resolver picks this file when $this->theme is set
 * to 'Overmind' and the controller asks for $this->layout =
 * 'dashboard'. It mirrors Overmind's default.ctp BS5 chrome path —
 * navbar.ctp (Bootstrap-5 dark navbar) + footerBS5 + mainOvermind
 * CSS + mispOvermind JS — but takes that path unconditionally,
 * skipping the $bootstrap5Pages whitelist check Overmind's
 * default.ctp uses. The dashboard is a BS5-style surface by design
 * (DD-08: "modern and pleasant", away from BS2.3 styling) so the
 * whitelist branch wouldn't add anything useful here.
 *
 * Notably skipped vs Overmind's default.ctp:
 *   - headerSection — the dashboard already emits its own
 *     `<header class="misp-dashboard-header">` with title +
 *     toolbar + Edit toggle + "⋯ More" dropdown. Layering
 *     Overmind's page-title bar on top would be redundant.
 *   - The debug accordion — keeping the dashboard surface free
 *     of MISP debug noise for this view. Cake's sql_dump element
 *     is still emitted below so debug builds aren't silenced.
 *   - The TomSelect topbar-filter init — no .topbar-filter
 *     elements on the dashboard surface.
 *   - The ajax-toggle / ajax-call click handler — dashboard
 *     widgets handle their own interactions via the §8.5 hook
 *     contract; the global ajax handler would compete.
 *
 * The dashboard's own CSS (dashboard.default.css + the dormant
 * midnight overlay) is loaded after mainOvermind so its tokens
 * and selectors win where they overlap.
 */
?>
<!DOCTYPE html>
<html lang="<?= Configure::read('Config.language') === 'eng' ? 'en' : Configure::read('Config.language') ?>">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="shortcut icon" href="<?= $baseurl ?>/img/favicon.png">
    <title><?= h($title_for_layout) . ' - ' . h(Configure::read('MISP.title_text') ?: 'MISP') ?></title>
    <?php echo $this->element('dashboard/theme_boot'); /* DD-51 no-FOUC light/dark boot */ ?>
    <?php
        $css = [
            ['bootstrap5-custom.min', ['preload' => true]],
            ['tom-select.bootstrap5.min', ['preload' => true]],
            ['mainOvermind', ['preload' => true]],
            ['fontawesome7.min', ['preload' => true]],
            ['dashboard/dashboard.default', ['preload' => true]],
            ['dashboard/dashboard.midnight'],
            // Loaded last so its rules win where they overlap with
            // dashboard.default.css. Cake's Helper::webroot() is
            // theme-aware and resolves this against
            // app/View/Themed/Overmind/webroot/css/dashboard/overmind.css
            // → /theme/Overmind/css/dashboard/overmind.css.
            ['dashboard/overmind', ['preload' => true]],
            ['print', ['media' => 'print']],
        ];
        if (Configure::read('MISP.custom_css')) {
            $css[] = preg_replace('/\.css$/i', '', Configure::read('MISP.custom_css'));
        }
        $js = [
            ['tom-select.complete.min', ['preload' => true]],
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
<body class="misp-dashboard-page"
      data-controller="<?= h($this->params['controller']) ?>"
      data-action="<?= h($this->params['action']) ?>">
    <div class="main-wrapper">
        <header>
            <?php
                // BS5 Overmind navbar — same build pattern as
                // Themed/Overmind/Layouts/default.ctp's BS5 branch.
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
                    'theme' => $theme,
                    'themesEnabled' => $themesEnabled,
                ];
                $menus = $this->Navbar->build($context);
                echo $this->element('navbar', [
                    'menus' => $menus,
                    'baseurl' => $baseurl,
                    'me' => $me ?? null,
                ]);
            ?>
        </header>
        <main role="main" class="content" style="padding-top:0;">
            <div id="flashOverlay">
                <div id="flashContainer">
                    <?= $this->Flash->render() ?>
                </div>
            </div>
            <div>
                <?= $this->fetch('content') ?>
            </div>
        </main>
    </div>

    <?= $this->element('footerBS5') ?>
    <?= $this->element('sql_dump') ?>

    <div id="popover_form" class="ajax_popover_form"></div>
    <div id="popover_form_large" class="ajax_popover_form ajax_popover_form_large"></div>
    <div id="popover_form_x_large" class="ajax_popover_form ajax_popover_form_x_large"></div>
    <div id="popover_matrix" class="ajax_popover_form ajax_popover_matrix"></div>
    <div id="popover_box" class="popover_box"></div>
    <div id="confirmation_box"></div>
    <div id="gray_out"></div>
    <div class="modal fade" id="mainModal" tabindex="-1">
        <div class="modal-dialog modal-dialog-centered" id="dynamicModalDialog">
            <div class="modal-content border-0" style="margin: auto;">
                <div class="modal-body p-0 m-0" id="mainModalBody"></div>
            </div>
        </div>
    </div>
    <div id="mainToastContainer" class="main-toast-container"></div>
    <div id="mainModalContainer"></div>
    <div id="api-tooltip" class="api-tooltip"></div>

    <div id="ajax_success_container" class="ajax_container">
        <div id="ajax_success" class="ajax_result ajax_success"></div>
    </div>
    <div id="ajax_fail_container" class="ajax_container">
        <div id="ajax_fail" class="ajax_result ajax_fail"></div>
    </div>
    <div class="loading">
        <div class="spinner"></div>
        <div class="loadingText"><?= __('Loading') ?></div>
    </div>

    <?php
    echo $this->element('genericElements/assetLoader', [
        'js' => [
            'bootstrap.bundle.min',
            'mispOvermind',
        ],
    ]);
    ?>

    <script>
        var baseurl = '<?= $baseurl ?>';
        var here = '<?php
                if (substr($this->params['action'], 0, 6) === 'admin_') {
                    echo $baseurl . '/admin/' . h($this->params['controller']) . '/' . h(substr($this->params['action'], 6));
                } else {
                    echo $baseurl . '/' . h($this->params['controller']) . '/' . h($this->params['action']);
                }
            ?>';

        document.addEventListener('DOMContentLoaded', function () {
            // Flash auto-dismiss (carried from Overmind default.ctp).
            const flash = document.getElementById('flashContainer');
            if (flash && flash.children.length > 0) {
                setTimeout(() => {
                    flash.classList.add('fade-out');
                    setTimeout(() => flash.remove(), 600);
                }, 5000);
            }
        });
    </script>
</body>
</html>
