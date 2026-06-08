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

            ['controller' => 'events', 'action' => 'index'],
            ['controller' => 'events', 'action' => 'add'],
            ['controller' => 'events', 'action' => 'edit'],
            ['controller' => 'events', 'action' => 'delete'],
            ['controller' => 'events', 'action' => 'view2'],
            ['controller' => 'events', 'action' => 'importChoice'],
            ['controller' => 'events', 'action' => 'automation'],
            ['controller' => 'events', 'action' => 'export'],
            ['controller' => 'events', 'action' => 'getEventInfoById'],

            ['controller' => 'attributes', 'action' => 'index'],
            ['controller' => 'attributes', 'action' => 'add'],
            ['controller' => 'attributes', 'action' => 'edit'],
            ['controller' => 'attributes', 'action' => 'delete'],

            ['controller' => 'sightings', 'action' => 'advanced'],

            ['controller' => 'collections', 'action' => 'index'],
            ['controller' => 'collections', 'action' => 'view'],
            ['controller' => 'collections', 'action' => 'add'],
            ['controller' => 'collections', 'action' => 'edit'],
            ['controller' => 'CollectionElements', 'action' => 'add'],
            ['controller' => 'CollectionElements', 'action' => 'index'],

            ['controller' => 'event_reports', 'action' => 'index'],
            ['controller' => 'event_reports', 'action' => 'view'],
            ['controller' => 'event_reports', 'action' => 'add'],
            ['controller' => 'event_reports', 'action' => 'edit'],


            ['controller' => 'EventReportTemplateVariables', 'action' => 'index'],
            ['controller' => 'EventReportTemplateVariables', 'action' => 'add'],
            ['controller' => 'EventReportTemplateVariables', 'action' => 'edit'],

            ['controller' => 'tags', 'action' => 'index'],
            ['controller' => 'tags', 'action' => 'add'],
            ['controller' => 'tags', 'action' => 'edit'],
            ['controller' => 'tags', 'action' => 'viewGraph'],

            ['controller' => 'tagCollections', 'action' => 'index'],
            ['controller' => 'tagCollections', 'action' => 'addWithTags'],
            ['controller' => 'tagCollections', 'action' => 'editWithTags'],

            ['controller' => 'taxonomies', 'action' => 'index'],
            ['controller' => 'taxonomies', 'action' => 'delete'],
            ['controller' => 'taxonomies', 'action' => 'view'],
            ['controller' => 'taxonomies', 'action' => 'addTag'],
            ['controller' => 'taxonomies', 'action' => 'disableTag'],

            ['controller' => 'templates', 'action' => 'index'],
            ['controller' => 'templates', 'action' => 'delete'],
            ['controller' => 'templates', 'action' => 'add'],
            ['controller' => 'templates', 'action' => 'view'],

            ['controller' => 'templateElements', 'action' => 'delete'],
            ['controller' => 'templateElements', 'action' => 'addV2'],
            ['controller' => 'templateElements', 'action' => 'editV2'],

            ['controller' => 'objectTemplates', 'action' => 'index'],
            ['controller' => 'objectTemplates', 'action' => 'delete'],
            ['controller' => 'objectTemplates', 'action' => 'add'],
            ['controller' => 'objectTemplates', 'action' => 'view'],

            ['controller' => 'object_relationships', 'action' => 'index'],
            ['controller' => 'object_relationships', 'action' => 'delete'],
            ['controller' => 'object_relationships', 'action' => 'add'],
            ['controller' => 'object_relationships', 'action' => 'edit'],

            ['controller' => 'warninglists', 'action' => 'index'],
            ['controller' => 'warninglists', 'action' => 'view'],
            ['controller' => 'warninglists', 'action' => 'add'],
            ['controller' => 'warninglists', 'action' => 'edit'],

            ['controller' => 'noticelists', 'action' => 'index'],
            ['controller' => 'noticelists', 'action' => 'view'],

            ['controller' => 'regexp', 'action' => 'admin_index'],
            ['controller' => 'regexp', 'action' => 'index'],
            ['controller' => 'regexp', 'action' => 'admin_add'],

            ['controller' => 'allowedlists', 'action' => 'admin_index'],
            ['controller' => 'allowedlists', 'action' => 'index'],
            ['controller' => 'allowedlists', 'action' => 'admin_add'],

            ['controller' => 'correlation_exclusions', 'action' => 'index'],
            ['controller' => 'correlation_exclusions', 'action' => 'add'],

            ['controller' => 'servers', 'action' => 'index'],
            ['controller' => 'servers', 'action' => 'add'],
            ['controller' => 'servers', 'action' => 'edit'],
            ['controller' => 'servers', 'action' => 'delete'],
            // ['controller' => 'servers', 'action' => 'cache'],
            // ['controller' => 'servers', 'action' => 'pull'],
            // ['controller' => 'servers', 'action' => 'push'],
            // ['controller' => 'servers', 'action' => 'testConnection'],
            // ['controller' => 'servers', 'action' => 'getRemoteSyncUser'],

            ['controller' => 'sightingdb', 'action' => 'index'],
            ['controller' => 'sightingdb', 'action' => 'add'],
            ['controller' => 'sightingdb', 'action' => 'edit'],
            ['controller' => 'sightingdb', 'action' => 'delete'],

            ['controller' => 'taxiiServers', 'action' => 'index'],
            ['controller' => 'taxiiServers', 'action' => 'add'],
            ['controller' => 'taxiiServers', 'action' => 'edit'],
            ['controller' => 'taxiiServers', 'action' => 'delete'],
            ['controller' => 'taxiiServers', 'action' => 'view'],

            ['controller' => 'cerebrates', 'action' => 'index'],
            ['controller' => 'cerebrates', 'action' => 'add'],
            ['controller' => 'cerebrates', 'action' => 'edit'],
            ['controller' => 'cerebrates', 'action' => 'delete'],
            ['controller' => 'cerebrates', 'action' => 'view'],
            ['controller' => 'cerebrates', 'action' => 'pull_sgs'],
            ['controller' => 'cerebrates', 'action' => 'pull_orgs'],

            ['controller' => 'communities', 'action' => 'index'],
            ['controller' => 'communities', 'action' => 'view'],
            ['controller' => 'communities', 'action' => 'requestAccess'],

            ['controller' => 'SharingGroups', 'action' => 'index'],
            ['controller' => 'SharingGroups', 'action' => 'add'],
            ['controller' => 'SharingGroups', 'action' => 'edit'],
            ['controller' => 'SharingGroups', 'action' => 'delete'],
            ['controller' => 'SharingGroups', 'action' => 'view'],

            ['controller' => 'SharingGroupBlueprints', 'action' => 'index'],
            ['controller' => 'SharingGroupBlueprints', 'action' => 'add'],
            ['controller' => 'SharingGroupBlueprints', 'action' => 'edit'],
            ['controller' => 'SharingGroupBlueprints', 'action' => 'delete'],
            ['controller' => 'SharingGroupBlueprints', 'action' => 'view'],
            ['controller' => 'SharingGroupBlueprints', 'action' => 'detach'],
            ['controller' => 'SharingGroupBlueprints', 'action' => 'execute'],
            ['controller' => 'SharingGroupBlueprints', 'action' => 'encodeSyncRule'],

            ['controller' => 'servers', 'action' => 'idTranslator'],
            ['controller' => 'event_templates', 'action' => 'index'],
            ['controller' => 'event_templates', 'action' => 'view'],
            ['controller' => 'event_templates', 'action' => 'import'],
            ['controller' => 'event_templates', 'action' => 'instantiate'],
            ['controller' => 'event_templates', 'action' => 'add'],
            ['controller' => 'event_templates', 'action' => 'edit'],
            ['controller' => 'event_templates', 'action' => 'preview'],
            ['controller' => 'event_templates', 'action' => 'update'],
            ['controller' => 'event_templates', 'action' => 'library_status'],


            ['controller' => 'api', 'action' => 'openapi'],
            ['controller' => 'api', 'action' => 'rest'],
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
                ['tom-select.bootstrap5.min', ['preload' => true]],
                ['mainOvermind', ['preload' => true]],
                ['fontawesome7.min', ['preload' => true]],
                ['print', ['media' => 'print']],
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
<body class="bg-light" data-controller="<?= h($this->params['controller']) ?>" data-action="<?= h($this->params['action']) ?>">
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
                            'theme' => $theme,
                            'themesEnabled' => $themesEnabled,
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
        <?php if ($useBootstrap5 && !($currentController === 'users' && $currentAction === 'login')): ?>
            <?php if (Configure::read('debug') > 0): ?>
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
                                    Debug Mode Enabled
                                </span>

                                <span id="debugErrorBadge"
                                    class="badge bg-success ms-3">
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
                            <!-- Errors are going to be injected here -->
                        </div>

                    </div>
                </div>
            </div>
            <?php endif; ?>
        <?php endif; ?>
        <!-- Flash & Content -->
        <main role="main" class="content" style="padding-top:<?php echo $topPadding; ?>px; !important;">
            <div id="flashOverlay">
                <div id="flashContainer">
                    <?= $this->Flash->render(); ?>
                </div>
            </div>
            <div>
                <?php
                if ($useBootstrap5 && !($currentController === 'users' && $currentAction === 'login')) {
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

    <!-- TO IMPROVE -->
    <?= $this->element('sql_dump') ?>

    <!-- Modals, Toasts and Popovers -->
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
                <div class="modal-body p-0 m-0" id="mainModalBody">
                </div>
        </div>
    </div>
    </div>
    <div id="mainToastContainer" class="main-toast-container"></div>
    <div id="mainModalContainer"></div>
    <div id="api-tooltip" class="api-tooltip"></div>


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
        var baseurl = '<?= $baseurl; ?>';
        var here = '<?php
                if (substr($this->params['action'], 0, 6) === 'admin_') {
                    echo $baseurl . '/admin/' . h($this->params['controller']) . '/' . h(substr($this->params['action'], 6));
                } else {
                    echo $baseurl . '/' . h($this->params['controller']) . '/' . h($this->params['action']);
                }
            ?>';
        <?php if (!Configure::read('MISP.disable_auto_logout') && isset($me) && $me): ?>
                //checkIfLoggedIn();
        <?php endif; ?>

        document.addEventListener('click', function(e) {
            const target = e.target.closest('.ajax-toggle, .ajax-call');
            if (!target) return;

            e.preventDefault();
            const url = target.dataset.url;

            fetch(url, { method: 'GET', headers: { 'X-Requested-With': 'XMLHttpRequest' } })
                .then(response => response.text())
                .then(data => {
                    const parser = new DOMParser();
                    const doc = parser.parseFromString(data, 'text/html');
                    const form = doc.querySelector('form');

                    if (form) {
                        const formData = new FormData(form);
                        return fetch(form.getAttribute('action'), {
                            method: 'POST',
                            body: new URLSearchParams(formData),
                            headers: { 'X-Requested-With': 'XMLHttpRequest' }
                        });
                    } else {
                        return Promise.resolve({ ok: true, message: 'Action executed.' });
                    }
                })
                .then(res => {
                    if (res.ok) {
                        showMessage('success', res.message || 'Field updated.');
                        location.reload();
                    } else {
                        throw new Error();
                    }
                })
                .catch(() => showMessage('fail', 'Action failed.'));
        });

        document.addEventListener('DOMContentLoaded', function () {
            // Flash management
            const flash = document.getElementById('flashContainer');
            if (flash && flash.children.length > 0) {
                setTimeout(() => {
                    flash.classList.add('fade-out');
                    setTimeout(() => flash.remove(), 600);
                }, 5000);
            }

            // Debug management
            const debugContainer = document.getElementById("debugAccordionContent");
            if (!debugContainer) return;

            const cakeErrors = document.querySelectorAll(".cake-error");
            const count = cakeErrors.length;
            const badge = document.getElementById("debugErrorBadge");

            badge.textContent = count + " error" + (count > 1 ? "s" : "");

            if (count > 0) {
                badge.classList.replace("bg-success", "bg-danger");
            } else {
                badge.classList.replace("bg-danger", "bg-success");
            }

            cakeErrors.forEach(error => debugContainer.appendChild(error));
        });

        document.querySelectorAll('.topbar-filter').forEach(function(el) {
            new TomSelect(el,{
                create:false,
                sortField:{
                    field:"text",
                    direction:"asc"
                }
            });
        });

        // Load an Ajax container and re-run its scripts
        function loadAjaxContainer(container) {
            if (!container || container.dataset.loaded) return;

            const url = container.dataset.url;
            if (!url) return;

            fetch(url, {
                headers: { 'X-Requested-With': 'XMLHttpRequest' }
            })
            .then(res => {
                if (!res.ok) throw new Error('HTTP ' + res.status);
                return res.text();
            })
            .then(html => {
                container.innerHTML = html;
                container.dataset.loaded = '1';

                // Re-execute the <script> tags in the injected fragment
                container.querySelectorAll('script').forEach(function (oldScript) {
                    const newScript = document.createElement('script');
                    if (oldScript.src) {
                        newScript.src = oldScript.src;
                    } else {
                        newScript.textContent = oldScript.textContent;
                    }
                    document.head.appendChild(newScript);
                    document.head.removeChild(newScript);
                });
            })
            .catch(() => {
                container.innerHTML = '<div class="text-danger">Error loading content</div>';
            });
        }

        // Lazy loading on tab click
        document.addEventListener('shown.bs.tab', function (event) {
            const target = event.target.getAttribute('data-bs-target') || event.target.getAttribute('href');
            const tabPane = document.querySelector(target);
            if (!tabPane) return;

            tabPane.querySelectorAll('.ajax-tab-content').forEach(loadAjaxContainer);
        });

        // The active tab loads immediately on startup
        document.addEventListener('DOMContentLoaded', function () {
            document.querySelectorAll('.tab-pane.active .ajax-tab-content').forEach(loadAjaxContainer);
        });

        const tooltip = document.getElementById('api-tooltip');
        tooltip.addEventListener('mouseenter', () => {
            isHoveringTooltip = true;
            clearTimeout(hoverTimeout);
        });

        tooltip.addEventListener('mouseleave', () => {
            isHoveringTooltip = false;
            scheduleHideTooltip();
        });
    </script>
</body>
</html>
