<div class="container-fluid">
    <div class="left-navbar">
        <a class="navbar-brand d-sm-block d-none" href="<?= $baseurl ?>">
            <div class="composed-app-icon-container">
                <span class="app-icon w-100 h-100" title="<?= __('MISP') ?>"></span>
            </div>
        </a>
        <button class="navbar-toggler d-sm-none" type="button" data-bs-toggle="collapse" data-bs-target="#app-sidebar" aria-controls="app-sidebar" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
    </div>
    <div class="center-navbar">
        <?= $this->element('layouts/header/header-breadcrumb'); ?>
    </div>
    <div class="right-navbar">
        <?= $this->element('layouts/header/header-right'); ?>
    </div>
</div>