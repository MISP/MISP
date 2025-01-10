<div class="d-flex">
    <div class="global-search-container d-md-block d-none">
        <span class="search-input-container">
            <input type="text" class="form-control d-inline-block" id="globalSearch" placeholder="<?= __('Search MISP...') ?>">
            <i class="icon <?= $this->FontAwesome->getClass('search') ?>"></i>
        </span>
        <div class="dropdown">
            <button type="button" class="dropdown-toggle d-none" id="dropdownMenuSearchAll" data-bs-toggle="dropdown" aria-haspopup="true" aria-expanded="false" data-bs-reference="parent"></button>
            <div class="global-search-result-container dropdown-menu dropdown-menu-end p-0 pt-2" aria-labelledby="dropdownMenuSearchAll">
                <div class="search-results-wrapper text-center"><?= __('- No result -') ?></div>
            </div>
        </div>
    </div>
    <div class="header-menu d-flex ms-1">
        <?= $this->element('layouts/header/header-notifications') ?>
        <?= $this->element('layouts/header/header-profile') ?>
    </div>
</div>
