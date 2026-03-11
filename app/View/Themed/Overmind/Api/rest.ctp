<?php

if ($this->Acl->canAccess('events', 'add')) {
    $this->set('headerActions', [
        [
            'url' => $baseurl . '/api/openapi',
            'label' => __('Open API'),
            'icon' => 'book-open'
        ]
    ]);
}

?>



<div class="container-fluid mt-4 mb-4">
    <div class="row">

        <!-- LEFT COLUMN (2/3) -->
        <div class="col-lg-8 d-flex flex-column gap-3">

            <?php
                echo $this->element('genericElementsBS5/card', [
                    'title' => __('Request configuration'),
                    'icon' => 'wrench',
                    'content' => $this->element('Api/View/configuration', ['header' => $header])
                ]);

                echo $this->element('genericElementsBS5/card', [
                     'title' => __('API Calls'),
                     'icon' => 'terminal',
                     'content' => $this->element('Api/View/calls', ['allAccessibleApis' => $allAccessibleApis])
                ]);

                echo $this->element('genericElementsBS5/card', [
                     'title' => __('Response'),
                     'icon' => 'chart-bar',
                     'content' => $this->element('Api/View/response', ['data' => $data ?? []])
                ]);
            ?>
        </div>


        <!-- RIGHT COLUMN (1/3) -->
        <div class="col-lg-4 d-flex flex-column gap-3">
            <?php
                // echo $this->element('genericElementsBS5/card', [
                //     'title' => __('History'),
                //     'content' => $this->element('api/view/history', ['event' => $event])
                // ]);

                // echo $this->element('genericElementsBS5/card', [
                //     'title' => __('Favorites'),
                //     'content' => $this->element('api/view/favorites', ['event' => $event])
                // ]);

                // echo $this->element('genericElementsBS5/card', [
                //     'title' => __('Predefined Queries'),
                //     'content' => $this->element('api/view/queries', ['event' => $event])
                // ]);
            ?>
        </div>

    </div>
</div>