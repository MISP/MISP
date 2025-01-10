<?php
$raw_alignments = $this->Hash->extract($row, $field['data_path']);
$alignments = '';
$canRemove = $this->request->getParam('prefix') !== 'Open';
if ($field['scope'] === 'individuals') {
    foreach ($raw_alignments as $alignment) {
        $alignments .= sprintf(
            '<div><span class="fw-bold">%s</span> @ %s <a href="#" class="fas fa-trash .text-reset .text-decoration-none" onClick="%s"></a></div>',
            h($alignment['type']),
            sprintf(
                '<a href="%s/organisations/view/%s">%s</a>',
                $baseurl,
                h($alignment['organisation']['id']),
                h($alignment['organisation']['name'])
            ),
            !$canRemove ? '' : sprintf(
                "UI.submissionModalForIndex(%s);",
                sprintf(
                    "'/alignments/delete/%s'",
                    h($alignment['id'])
                )
            )
        );
    }
} else if ($field['scope'] === 'organisations') {
    foreach ($raw_alignments as $alignment) {
        $alignments .= sprintf(
            '<div>[<span class="fw-bold">%s</span>] %s <a href="#" class="fas fa-trash .text-reset .text-decoration-none" onClick="%s"></a></div>',
            h($alignment['type']),
            sprintf(
                '<a href="%s/individuals/view/%s">%s</a>',
                $baseurl,
                h($alignment['individual']['id']),
                h($alignment['individual']['email'])
            ),
            !$canRemove ? '' : sprintf(
                "UI.submissionModalForIndex(%s);",
                sprintf(
                    "'/alignments/delete/%s'",
                    h($alignment['id'])
                )
            )
        );
    }
}
echo $alignments;
