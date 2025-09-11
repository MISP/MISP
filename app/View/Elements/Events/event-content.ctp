<?php

$objectHtml = '<i>objects</i>';
$attributeHtml = '<div id="attributes-table-container">Loading...</div>';
$reporttHtml = 'reports';
$eventGraphHtml = 'eventgraph';
$timelineHtml = 'timeline';
$attackHtml = 'Include matrix, preventive measures & mitigations ';
$discussionHtml = 'discussion';

echo $this->Bootstrap->tabs([
   'horizontal-position' => 'top',
    'fill-header' => true,
    'card' => true,
    'id' => 'event-content-tabs',
    'data' => [
        'navs' => [
            [
                'id' => 'event-objects',
                'data-target-url' => $baseurl . '/objects/index/' . intval($event['Event']['id']),
                'html' => sprintf(
                    '%s %s',
                    $this->Bootstrap->icon($iconToTableMapping['Objects']),
                    __('Objects') . $this->Bootstrap->badge(['text' => $stats['stat_counts']['objects'],
                        'variant' => 'primary',
                    ])
                ),
                'active' => true,
            ],
            [
                'id' => 'event-attributes',
                'data-target-url' => $baseurl . '/attributes/index/eventid:' . intval($event['Event']['id']),
                'html' => sprintf(
                    '%s %s',
                    $this->Bootstrap->icon($iconToTableMapping['Attributes']),
                    __('Attributes') . $this->Bootstrap->badge(['text' => $stats['stat_counts']['attributes'],
                        'variant' => 'primary',
                    ])
                ),
            ],
            [
                'html' => sprintf(
                    '%s %s',
                    $this->Bootstrap->icon($iconToTableMapping['EventReports']),
                    __('Reports') . $this->Bootstrap->badge(['text' => $stats['stat_counts']['eventreports'],
                        'variant' => $stats['stat_counts']['eventreports'] > 0 ? 'warning' : 'primary',
                    ])
                ),
            ],
            ['html' => sprintf('%s %s', $this->Bootstrap->icon('diagram-project'), __('Event Graph')),],
            ['html' => sprintf('%s %s', $this->Bootstrap->icon('timeline'), __('Event Timeline')),],
            [
                'html' => $this->Bootstrap->node('span', [
                    'class' => ['text-uppercase'],
                    'style' => 'color: #C8452B;'
                ], 'ATT&CK' . '<sup>®</sup>'),
            ],
            [
                'html' => sprintf(
                    '%s %s',
                    $this->Bootstrap->icon('comments'),
                    __('Discussion') . $this->Bootstrap->badge(['text' => $stats['stat_counts']['discussions'],
                        'variant' => $stats['stat_counts']['discussions'] > 0 ? 'warning' : 'primary',
                    ])
                ),
            ],
        ],
        'content' => [
            $objectHtml,
            $attributeHtml,
            $reporttHtml,
            $eventGraphHtml,
            $timelineHtml,
            $attackHtml,
            $discussionHtml,
        ]
    ]
]);
?>

<script>
document.addEventListener('DOMContentLoaded', () => {
  const loaded = {};

  // Listen for Bootstrap tab activation
  document.querySelectorAll('#event-content-tabs a[data-bs-toggle="tab"]')
    .forEach(tab => {
      tab.addEventListener('shown.bs.tab', async (event) => {
        const targetPaneId = tab.getAttribute('href');
        const targetPane = document.querySelector(targetPaneId);
        const targetUrl  = tab.dataset.targetUrl;
        if (!targetUrl) return;

        if (loaded[tab.id]) return;

        try {
          targetPane.innerHTML = '<div class="text-muted p-3"><i class="bi bi-arrow-repeat me-2 spin"></i>Loading…</div>';
          const response = await fetch(
            targetUrl, 
            {
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                }
            }
        );
            if (!response.ok) throw new Error(`HTTP ${response.status}`);

            const html = await response.text();
            targetPane.innerHTML = html;

            loaded[tab.id] = true;
        } catch (err) {
            targetPane.innerHTML =`<div class="alert alert-danger m-3">Could not load content: ${err.message}</div>`;
        }
      });
    });
});

// Optional: tiny CSS for spinner icon
const style = document.createElement('style');
style.textContent = `
  .spin { animation: spin 1s linear infinite; }
  @keyframes spin { 100% { transform: rotate(360deg); } }
`;
document.head.appendChild(style);



</script>
