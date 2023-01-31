<?php
$alignments = '';
$extracted = $data;
if (!empty($field['path'])) {
    if (strpos('.', $field['path']) !== false) {
        $extracted = Cake\Utility\Hash::extract($data, empty($field['path']) ? 'individual' : $field['path']);
    } else {
        $extracted = $data[$field['path']];
    }
}
if ($field['scope'] === 'individuals') {
    foreach ($extracted['alignments'] as $alignment) {
        $alignments .= sprintf(
            '<div><span class="fw-bold">%s</span> @ %s <a href="#" class="fas fa-trash" onClick="%s"></a></div>',
            h($alignment['type']),
            sprintf(
                '<a href="%s/organisations/view/%s">%s</a>',
                $baseurl,
                h($alignment['organisation']['id']),
                h($alignment['organisation']['name'])
            ),
            sprintf(
                "UI.submissionModalForSinglePage(%s);",
                sprintf(
                    "'/alignments/delete/%s'",
                    $alignment['id']
                )
            )
        );
    }
} else if ($field['scope'] === 'organisations') {
    foreach ($extracted['alignments'] as $alignment) {
        $alignments .= sprintf(
            '<div>[<span class="fw-bold">%s</span>] %s <a href="#" class="fas fa-trash" onClick="%s"></a></div>',
            h($alignment['type']),
            sprintf(
                '<a href="%s/individuals/view/%s">%s</a>',
                $baseurl,
                h($alignment['individual']['id']),
                h($alignment['individual']['email'])
            ),
            sprintf(
                "UI.submissionModalForSinglePage(%s);",
                sprintf(
                    "'/alignments/delete/%s'",
                    $alignment['id']
                )
            )
        );
    }
}
echo sprintf(
    '<div class="alignments-list">%s</div><div class="alignments-add-container"><button class="alignments-add-button btn btn-primary btn-sm" onclick="%s">%s</button></div>',
    $alignments,
    sprintf(
        "UI.submissionModalForSinglePage('/alignments/add/%s/%s');",
        h($field['scope']),
        h($extracted['id'])
    ),
    $field['scope'] === 'individuals' ? __('Add organisation') : __('Add individual')
);
