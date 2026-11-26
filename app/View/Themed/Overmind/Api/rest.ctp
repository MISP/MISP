<?php
$this->set('headerTitle', __('REST Client'));
$this->set('headerDescription', '');
$this->set('headerActions', [
    [
        'url' => $baseurl . '/api/openapi',
        'label' => __('Open API'),
        'type' => 'navigate',
        'icon' => 'book-open',
    ],
]);

echo $this->element('genericElements/assetLoader', [
    'js' => ['restOvermind'],
]);
?>
<div class="container-fluid">
    <div class="row g-3 align-items-start">
        <div class="col-lg-4 col-xxl-3 order-2 order-lg-1">
            <?= $this->element('Api/View/library', ['allAccessibleApis' => $allAccessibleApis]) ?>
        </div>
        <div class="col-lg-8 col-xxl-9 order-1 order-lg-2 d-flex flex-column gap-3" id="rest-client-container">
            <?= $this->element('Api/View/configuration') ?>
            <?= $this->element('Api/View/response') ?>
        </div>
    </div>
</div>
