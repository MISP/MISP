<!DOCTYPE html>
<html>

<head>
    <?= $this->Html->charset() ?>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>
        <?= 'MISP' ?>:
        <?= $this->fetch('title') ?>
    </title>
    <?= $this->Html->meta('icon') ?>
    <?php
    echo $this->Html->css('themes/bootstrap-' . $bsTheme);
    echo $this->Html->css('themes/theme-' . $bsTheme);
    ?>
    <?= $this->Html->css('login.css') ?>
    <?= $this->Html->css('main.css') ?>
    <?= $this->Html->css('font-awesome') ?>
    <?= $this->Html->css('fa-brand') ?>
    <?= $this->Html->css('fa-solid') ?>
    <?= $this->Html->script('jquery-3.5.1.min.js') ?>
    <?= $this->Html->script('popper.min.js') ?>
    <?= $this->Html->script('bootstrap.bundle.js') ?>
    <?= $this->Html->script('main.js') ?>
    <?= $this->fetch('meta') ?>
    <?= $this->fetch('css') ?>
    <?= $this->fetch('script') ?>
    <?= $this->Html->meta('favicon.png', '/img/favicon.png', ['type' => 'icon']); ?>
</head>

<body>
    <div class="position-absolute"></div>
    <?= $this->Flash->render() ?>
    <?= $this->fetch('content') ?>
    <div id="mainModal" class="modal fade" tabindex="-1" role="dialog" aria-labelledby="mediumModalLabel" aria-hidden="true"></div>
</body>

</html>