<?php
$collection = $data['Collection'];
$railCards = $railCards ?? [];

App::uses('CollectionType', 'Tools');

$titleHtml = h($collection['name'] ?? __('Collection'));
if (!empty($collection['type'])) {
    $typeLabel = CollectionType::label($collection['type']);
    $titleHtml = sprintf(
        '<span class="badge d-inline-flex align-items-center align-self-center py-1 me-2"'
        . ' style="background:rgba(var(--bs-primary-rgb),.12);color:var(--bs-primary);'
        . 'border:1px solid rgba(var(--bs-primary-rgb),.25);font-size:.55em;"'
        . ' data-bs-toggle="tooltip" title="%s" aria-label="%s"><i class="%s"></i></span>',
        h($typeLabel),
        h($typeLabel),
        h(CollectionType::icon($collection['type']))
    ) . $titleHtml;
}
// How far the investigation went: said by whoever may edit it, shown to all once said
$analysis = (int)($collection['analysis'] ?? 0);
$analysisLabels = [__('Initial'), __('Ongoing'), __('Completed')];
$tone = ['secondary', 'info', 'success'][$analysis] ?? 'secondary';
$canSetAnalysis = !empty($me) && $this->Acl->canAccess('collections', 'analysis')
    && ClassRegistry::init('Collection')->canModify($me, $collection);
if ($canSetAnalysis) {
    $items = '';
    foreach ($analysisLabels as $level => $label) {
        $items .= sprintf(
            '<li><button type="button" class="dropdown-item d-flex align-items-center gap-2" data-collection-analysis="%d"%s>'
            . '<i class="fas fa-check fa-fw%s" aria-hidden="true"></i><span>%s</span></button></li>',
            $level,
            $level === $analysis ? ' aria-current="true"' : '',
            $level === $analysis ? '' : ' invisible',
            h($label)
        );
    }
    if ((int)($collection['distribution'] ?? 0) !== 0) {
        $items .= '<li><hr class="dropdown-divider"></li><li><p class="dropdown-item-text small text-body-secondary mb-0" style="max-width:17rem;white-space:normal;">'
            . h(__('Partners see the change once the collection is published.')) . '</p></li>';
    }
    $titleHtml .= sprintf(
        '<span class="dropdown d-inline-flex align-self-center ms-2" data-collection-analysis-url="%1$s" data-collection-analysis-failed="%2$s">'
        . '<button type="button" class="badge rounded-pill bg-%3$s-subtle text-%3$s-emphasis border border-%3$s-subtle dropdown-toggle"'
        . ' style="font-size:.4em;font-weight:600;" data-bs-toggle="dropdown" aria-expanded="false"'
        . ' data-bs-popper-config=\'{"strategy":"fixed"}\' title="%4$s" aria-label="%5$s">%6$s</button>'
        // Above the sticky tab bar it opens over
        . '<ul class="dropdown-menu" style="--bs-dropdown-zindex:1045;font-weight:400;letter-spacing:normal;"><li><h6 class="dropdown-header">%4$s</h6></li>%7$s</ul></span>',
        h($baseurl . '/collections/analysis/' . (int)$collection['id'] . '.json'),
        h(__('The status was not changed')),
        $tone,
        h(__('How far the investigation went')),
        h(__('Status: %s, change it', $analysisLabels[$analysis] ?? '')),
        h($analysisLabels[$analysis] ?? ''),
        $items
    );
} elseif ($analysis > 0) {
    $titleHtml .= sprintf(
        '<span class="badge rounded-pill align-self-center ms-2 bg-%1$s-subtle text-%1$s-emphasis border border-%1$s-subtle"'
        . ' style="font-size:.4em;font-weight:600;" title="%2$s">%3$s</span>',
        $tone,
        h(__('How far the investigation went')),
        h($analysisLabels[$analysis] ?? '')
    );
}
$this->set('headerTitleHtml', $titleHtml);
$this->set('headerCountText', '');

$this->set('headerIdentity', $collection);
$this->set('headerTimestamps', $collection);

echo $this->element('genericElementsBS5/Layout/view_layout', [
    'data' => $data,
    'ownership' => [
        'orgc' => $collection['Orgc'] ?? [],
        'org' => $collection['Org'] ?? [],
        'user' => $collection['User'] ?? [],
        'distribution' => $collection['distribution'] ?? null,
        'sharingGroup' => $collection['SharingGroup'] ?? [],
    ],
    'tabs' => [
        [
            'id' => 'general',
            'title' => __('General'),
            'icon' => 'fas fa-info-circle',
            'left' => [
                'Collections/View/collection_general',
                'Collections/View/collection_elements_card',
            ],
            'right' => array_merge([
                'Collections/View/collection_actions',
                'Collections/View/collection_analyst_data',
                'Collections/View/collection_graphs',
            ], $this->RailCard->rail($railCards, [
                'collection-inventory', 'collection-sources',
            ], 'general')),
        ],
        [
            'id' => 'elements',
            'title' => __('Elements'),
            'icon' => 'fas fa-file',
            'left' => [
                'Collections/View/collection_elements',
            ],
            'right' => $this->RailCard->rail($railCards, ['collection-inventory'], 'elements'),
        ]
    ]
]);
?>
<script>
// The status pill's menu: the new status is saved, then the page shows what it changed
document.addEventListener('click', function (e) {
    var item = e.target.closest && e.target.closest('[data-collection-analysis]');
    if (!item || item.getAttribute('aria-current') === 'true') return;
    var wrap = item.closest('[data-collection-analysis-url]');
    fetch(wrap.getAttribute('data-collection-analysis-url'), {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Accept': 'application/json', 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest', 'X-CSRF-Token': window.csrfToken || '' },
        body: JSON.stringify({ analysis: +item.getAttribute('data-collection-analysis') })
    }).then(function (r) {
        return r.json().catch(function () { return {}; }).then(function (body) {
            if (!r.ok) throw new Error(body.message || ('HTTP ' + r.status));
        });
    }).then(function () {
        window.location.reload();
    }, function (err) {
        if (typeof showToast === 'function') showToast(wrap.getAttribute('data-collection-analysis-failed') + ': ' + err.message, 'danger');
    });
});
</script>
