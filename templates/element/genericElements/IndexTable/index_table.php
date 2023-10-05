<?php

use Cake\Utility\Text;
/*
*  echo $this->element('/genericElements/IndexTable/index_table', [
*      'top_bar' => (
*          // search/filter bar information compliant with ListTopBar
*      ),
*      'data' => [
        // the actual data to be used
*      ),
*      'fields' => [
*          // field list with information for the paginator, the elements used for the individual cells, etc
*      ),
*      'title' => optional title,
*      'description' => optional description,
*      'notice' => optional alert to be placed at the top,
*      'index_statistics' => optional statistics to be displayed for the index,
*      'primary_id_path' => path to each primary ID (extracted and passed as $primary to fields)
*  ));
*
*/

$newMetaFields = [];
if (!empty($requestedMetaFields)) { // Create mapping for new index table fields on the fly
    foreach ($requestedMetaFields as $requestedMetaField) {
        $template_id = $requestedMetaField['template_id'];
        $meta_template_field_id = $requestedMetaField['meta_template_field_id'];
        $viewElementCandidate = $meta_templates[$template_id]['meta_template_fields'][$meta_template_field_id]['index_type'];
        $viewElementCandidatePath = '/genericElements/IndexTable/Fields/' . $viewElementCandidate;
        $newMetaFields[] = [
            'name' => $meta_templates[$template_id]['meta_template_fields'][$meta_template_field_id]['field'],
            'data_path' => "MetaTemplates.{$template_id}.meta_template_fields.{$meta_template_field_id}.metaFields.{n}.value",
            'element' => $this->elementExists($viewElementCandidatePath) ? $viewElementCandidate : 'generic_field',
            '_metafield' => true,
            '_automatic_field' => true,
        ];
    }
}
$data['fields'] = array_merge($data['fields'], $newMetaFields);

$tableRandomValue = Cake\Utility\Security::randomString(8);
$html = '<div id="table-container-' . h($tableRandomValue) . '">';
if (!empty($data['title'])) {
    if (empty($embedInModal)) {
        $html .= Text::insert(
            '<h2 class="fw-light">:title :help</h2>',
            [
                'title' => h($this->ValueGetter->get($data['title'])),
                'help' => $this->Bootstrap->icon(
                    'info',
                    [
                    'class' => ['fs-6', 'align-text-top',],
                    'title' => empty($data['description']) ? '' : h($data['description']),
                    'attrs' => [
                        'data-bs-toggle' => 'tooltip',
                    ]
                    ]
                ),
            ]
        );
    } else {
        $pageTitle = $this->Bootstrap->node('h5', [], h($this->ValueGetter->get($data['title'])));
    }
}

if(!empty($notice)) {
    $html .=  $this->Bootstrap->alert($notice);
}

if (!empty($modelStatistics)) {
    $html .=  $this->element(
        'genericElements/IndexTable/Statistics/index_statistic_scaffold',
        [
        'statistics' => $modelStatistics,
        ]
    );
}


$html .= '<div class="panel">';
if (!empty($data['html'])) {
    $html .= sprintf('<div>%s</div>', $data['html']);
}
$skipPagination = isset($data['skip_pagination']) ? $data['skip_pagination'] : 0;
if (!$skipPagination) {
    $paginationData = !empty($data['paginatorOptions']) ? $data['paginatorOptions'] : [];
    if (!empty($embedInModal)) {
        $paginationData['update'] = ".modal-main-{$tableRandomValue}";
    }
    $html .= $this->element(
        '/genericElements/IndexTable/pagination',
        [
            'paginationOptions' => $paginationData,
            'tableRandomValue' => $tableRandomValue
        ]
    );
    $html .= $this->element(
        '/genericElements/IndexTable/pagination_links'
    );
}
if (!empty($data['top_bar']) && empty($skipTableToolbar)) {
    $multiSelectData = getMultiSelectData($data['top_bar']);
    if (!empty($multiSelectData)) {
        $multiSelectField = [
            'element' => 'selector',
            'class' => 'short',
            'data' => $multiSelectData['data']
        ];
        array_unshift($data['fields'], $multiSelectField);
    }
    $html .= $this->element(
        '/genericElements/ListTopBar/scaffold',
        [
            'data' => $data['top_bar'],
            'table_data' => $data,
            'tableRandomValue' => $tableRandomValue
        ]
    );
}
$rows = '';
$row_element = isset($data['row_element']) ? $data['row_element'] : 'row';
$options = isset($data['options']) ? $data['options'] : [];
$actions = isset($data['actions']) ? $data['actions'] : [];
if ($this->request->getParam('prefix') === 'Open') {
    $actions = [];
}
$dblclickActionArray = !empty($actions) ? $this->Hash->extract($actions, '{n}[dbclickAction]') : [];
$dbclickAction = '';
foreach ($data['data'] as $k => $data_row) {
    $primary = null;
    if (!empty($data['primary_id_path'])) {
        $primary = $this->Hash->extract($data_row, $data['primary_id_path'])[0];
    }
    if (!empty($dblclickActionArray)) {
        $dbclickAction = sprintf("changeLocationFromIndexDblclick(%s)", $k);
    }
    $rows .= sprintf(
        '<tr data-row-id="%s" %s %s class="%s %s">%s</tr>',
        h($k),
        empty($dbclickAction) ? '' : 'ondblclick="' . $dbclickAction . '"',
        empty($primary) ? '' : 'data-primary-id="' . $primary . '"',
        empty($data['row_modifier']) ? '' : h($data['row_modifier']($data_row)),
        empty($data['class']) ? '' : h($data['row_class']),
        $this->element(
            '/genericElements/IndexTable/' . $row_element,
            [
                'k' => $k,
                'row' => $data_row,
                'fields' => $data['fields'],
                'options' => $options,
                'actions' => $actions,
                'primary' => $primary,
                'tableRandomValue' => $tableRandomValue
            ]
        )
    );
}
$tbody = '<tbody>' . $rows . '</tbody>';
$html .= sprintf(
    '<table class="table table-hover" id="index-table-%s" data-table-random-value="%s" data-reload-url="%s">%s%s</table>',
    $tableRandomValue,
    $tableRandomValue,
    h($this->Url->build(['action' => $this->request->getParam('action'),])),
    $this->element(
        '/genericElements/IndexTable/headers',
        [
            'fields' => $data['fields'],
            'paginator' => $this->Paginator,
            'actions' => (empty($actions) ? false : true),
            'tableRandomValue' => $tableRandomValue
        ]
    ),
    $tbody
);
if (!$skipPagination) {
    $html .= $this->element('/genericElements/IndexTable/pagination_counter', $paginationData);
    $html .= $this->element('/genericElements/IndexTable/pagination_links');
}
$html .= '</div>';
$html .= '</div>';

if (!empty($embedInModal)) {
    echo $this->Bootstrap->modal(
        [
        'titleHtml' => $pageTitle ?? '',
        'bodyHtml' =>  $html,
        'size' => 'xl',
        'type' => 'ok-only',
        'modalClass' => "modal-main-{$tableRandomValue}"
        ]
    );
} else {
    echo $html;
}
?>
<script type="text/javascript">
    $(document).ready(function() {
        $('#index-table-<?= $tableRandomValue ?>').data('data', <?= json_encode($data['data']) ?>);
        $('.privacy-toggle').on('click', function() {
            var $privacy_target = $(this).parent().find('.privacy-value');
            if ($(this).hasClass('fa-eye')) {
                $privacy_target.text($privacy_target.data('hidden-value'));
                $(this).removeClass('fa-eye');
                $(this).addClass('fa-eye-slash');
            } else {
                $privacy_target.text('****************************************');
                $(this).removeClass('fa-eye-slash');
                $(this).addClass('fa-eye');
            }
        });

        var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
        var tooltipList = tooltipTriggerList.map(function(tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl)
        })
    });
</script>

<?php
function getMultiSelectData($topbar)
{
    foreach ($topbar['children'] as $child) {
        if (!empty($child['type']) && $child['type'] == 'multi_select_actions') {
            return $child;
        }
    }
    return [];
}
