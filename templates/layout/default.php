<?php
/**
 * CakePHP(tm) : Rapid Development Framework (https://cakephp.org)
 * Copyright (c) Cake Software Foundation, Inc. (https://cakefoundation.org)
 *
 * Licensed under The MIT License
 * For full copyright and license information, please see the LICENSE.txt
 * Redistributions of files must retain the above copyright notice.
 *
 * @copyright     Copyright (c) Cake Software Foundation, Inc. (https://cakefoundation.org)
 * @link          https://cakephp.org CakePHP(tm) Project
 * @since         0.10.0
 * @license       https://opensource.org/licenses/mit-license.php MIT License
 * @var \App\View\AppView $this
 */
use Cake\Core\Configure;

$cakeDescription = 'Cerebrate';

$sidebarOpen = $loggedUser->user_settings_by_name_with_fallback['ui.sidebar.expanded']['value'];
?>
<!DOCTYPE html>
<html>
<head>
    <?= $this->Html->charset() ?>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>
        <?= $cakeDescription ?>:
        <?= $this->fetch('title') ?>
    </title>
    <?= $this->Html->meta('icon') ?>
    <?php
        echo $this->Html->css('themes/theme-' . $bsTheme);
    ?>
    <?= $this->Html->css('main.css') ?>
    <?= $this->Html->css('font-awesome') ?>
    <?= $this->Html->css('layout.css') ?>
    <?= $this->Html->script('jquery-3.5.1.min.js') ?>
    <?= $this->Html->script('bootstrap.bundle.js') ?>
    <?= $this->Html->script('main.js') ?>
    <?= $this->Html->script('utils.js') ?>
    <?= $this->Html->script('bootstrap-helper.js') ?>
    <?= $this->Html->script('api-helper.js') ?>
    <?= $this->Html->script('select2.min.js') ?>
    <?= $this->Html->script('table-settings.js') ?>
    <?= $this->Html->script('CodeMirror/codemirror.js') ?>
    <?= $this->Html->script('CodeMirror/mode/javascript/javascript') ?>
    <?= $this->Html->script('CodeMirror/addon/hint/show-hint') ?>
    <?= $this->Html->script('CodeMirror/addon/lint/lint') ?>
    <?= $this->Html->script('CodeMirror/addon/lint/jsonlint') ?>
    <?= $this->Html->script('CodeMirror/addon/lint/json-lint') ?>
    <?= $this->Html->script('CodeMirror/addon/edit/matchbrackets') ?>
    <?= $this->Html->script('CodeMirror/addon/edit/closebrackets') ?>
    <?= $this->Html->script('CodeMirror/addon/display/placeholder') ?>
    <?= $this->Html->css('CodeMirror/codemirror') ?>
    <?= $this->Html->css('CodeMirror/codemirror-additional') ?>
    <?= $this->Html->css('CodeMirror/addon/hint/show-hint') ?>
    <?= $this->Html->css('CodeMirror/addon/lint/lint') ?>
    <?= $this->Html->css('select2.min') ?>
    <?= $this->Html->css('select2-bootstrap5-vars') ?>
    <?= $this->Html->script('apexcharts.min') ?>
    <?= $this->Html->script('moment-with-locales.min') ?>
    <?= $this->Html->css('apexcharts') ?>

    <?= $this->fetch('meta') ?>
    <?= $this->fetch('css') ?>
    <?= $this->fetch('script') ?>

    <?= $this->Html->script('Tags.tagging') ?>
    <?= $this->Html->css('Tags.tagging') ?>

    <?= $this->Html->meta('favicon.ico', '/img/favicon.ico', ['type' => 'icon']); ?>
</head>
<body>
    <div class="main-wrapper">
        <header class="navbar top-navbar navbar-dark">
            <?= $this->element('layouts/header') ?>
        </header>
        <nav id="app-sidebar" class="collapse d-sm-block sidebar <?= !empty($sidebarOpen) ? 'expanded' : '' ?>">
            <?= $this->element('layouts/sidebar') ?>
        </nav>
        <main role="main" class="content">
            <div class="container-fluid mt-1">
                <?= $this->Flash->render() ?>
                <?= $this->fetch('actionBar') ?>
                <?= $this->fetch('content') ?>
            </div>
        </main>
    </div>
    <div id="mainModal" class="modal fade" tabindex="-1" role="dialog" aria-labelledby="mediumModalLabel" aria-hidden="true"></div>
    <div id="mainToastContainer" class="main-toast-container"></div>
    <div id="mainModalContainer"></div>
</body>

<script>
    const bsTheme = '<?= h($bsTheme); ?>'
    $.fn.select2.defaults.set('theme', 'bootstrap-5');
</script>
</html>
