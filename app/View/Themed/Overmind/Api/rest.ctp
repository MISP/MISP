<?php
// Title of the index displayed in the header section, leaving it empty will fallback to controller name
$headerTitle = __('REST Client');

// Description displayed under the title in the header section, leave empty if not needed
$headerDescription = __('');

// Actions displayed as buttons in the header section, leave empty if not needed
$headerActions = [
    [
        'url' => $baseurl . '/api/openapi',
        'label' => __('Open API'),
        'type' => 'navigate',
        'icon' => 'book-open'
    ]
];

$this->set('headerTitle', $headerTitle);
$this->set('headerDescription', $headerDescription);
$this->set('headerActions', $headerActions);


echo $this->element('genericElements/assetLoader', array(
    'js' => array(
        'restOvermind'
    )
));
?>


<div class="container-fluid">
    <div class="row">
        <!-- LEFT COLUMN  -->
        <div class="col-lg-8 d-flex flex-column gap-3" id="rest-client-container">

            <?php
                echo $this->element('genericElementsBS5/Cards/card_info', [
                    'title' => __('Request configuration'),
                    'icon' => 'wrench',
                    'collapsed' => false,
                    'content' => $this->element('Api/View/configuration')
                ]);

                echo $this->element('genericElementsBS5/Cards/card_collapsible', [
                     'title' => __('API Tools'),
                     'icon' => 'terminal',
                     'collapsed' => true,
                     'content' => $this->element('Api/View/tools')
                ]);

                echo $this->element('genericElementsBS5/Cards/card_collapsible', [
                     'title' => __('Response'),
                     'icon' => 'chart-bar',
                     'collapsed' => true,
                     'content' => $this->element('Api/View/response')
                ]);
            ?>
        </div>

        <!-- RIGHT COLUMN -->
        <div class="col-lg-4 d-flex flex-column gap-3">
            <?php
                echo $this->element('genericElementsBS5/Cards/card_collapsible', [
                    'title' => __('History'),
                    'icon' => 'clock-rotate-left',
                    'collapsed' => true,
                    'maxHeight' => '500px',
                    'content' => $this->element('Api/View/history')
                ]);

                echo $this->element('genericElementsBS5/Cards/card_collapsible', [
                    'title' => __('Bookmarks'),
                    'icon' => 'star',
                    'collapsed' => true,
                    'maxHeight' => '500px',
                    'content' => $this->element('Api/View/bookmarks')
                ]);

                echo $this->element('genericElementsBS5/Cards/card_collapsible', [
                    'title' => __('Templates'),
                    'icon' => 'list',
                    'collapsed' => false,
                    'maxHeight' => '800px',
                    'content' => $this->element('Api/View/templates', ['allAccessibleApis' => $allAccessibleApis])
                ]);
            ?>
        </div>

    </div>
</div>


<script>
var baseurl = '<?= $baseurl; ?>';

let allValidApis = {};
fetch(baseurl + '/api/getAllApis')
    .then(res => res.json())
    .then(data => {
        allValidApis = data.allValidApis || {};
    });
</script>
