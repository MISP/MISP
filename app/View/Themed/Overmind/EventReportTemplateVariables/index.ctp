<?php
// Title of the index displayed in the header section, leaving it empty will fallback to controller name
$headerTitle = __('Event Report Template Variables');

// Description displayed under the title in the header section, leave empty if not needed
$headerDescription = __('Reusable snippets you can drop into an Event Report. Type the token anywhere in a report and it is replaced by the content defined here.');

// Actions displayed as buttons in the header section, leave empty if not needed
$headerActions = [];
if ($this->Acl->canAccess('EventReportTemplateVariables', 'add')) {
    $headerActions[] = [
        'type' => 'modal',
        'label' => __('Add Variable'),
        'icon' => 'plus',
        'url' => $baseurl . '/EventReportTemplateVariables/add'
    ];
}

$this->set('headerTitle', $headerTitle);
$this->set('headerDescription', $headerDescription);
$this->set('headerActions', $headerActions);


$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'EventReportTemplateVariable.id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'id',
        'data_path' => 'EventReportTemplateVariable.id',
        'element' => 'id',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Variable'),
        'sort' => 'EventReportTemplateVariable.name',
        'data_path' => 'EventReportTemplateVariable.name',
        'element' => 'event_report_template_name',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Expands to'),
        'sort' => 'EventReportTemplateVariable.value',
        'data_path' => 'EventReportTemplateVariable.value',
        'element' => 'event_report_template_value',
        'card_section' => 'body',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'EventReportTemplateVariable.id',
        'card_section' => 'extra',
        'display_in' => ['table', 'card'],
        'actions' => [
            [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/EventReportTemplateVariables/edit/%id%',
                'requirement' => $isSiteAdmin
            ],
            [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/EventReportTemplateVariables/deleteSelection/%id%',
                'class' => 'text-danger',
                'requirement' => $isSiteAdmin
            ]
        ]
    ],
];

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $data,
            'filter_bar' => [
                'pull' => 'right',
                'children' => [
                    [
                        'type' => 'search',
                        'button' => 'Search',
                        'placeholder' => 'Search in all fields',
                        'name'        => '',
                        'mode'        => 'quickFilter',
                    ],
                ],
                'delete' => '/deleteSelection',
            ],
            'fields' => $fields,
            'card_element' => 'EventReportTemplateVariables/variable_card',
            'cards_per_row' => 3,
        ]
    ],
    'item_url' => '/EventReportTemplateVariables'
]);
?>

<script>
/*
 * Two interactions, both delegated on document because the table view and the
 * card view are in the DOM at the same time and the filter bar re-renders the
 * index in place.
 *
 *   - clicking a token copies `{{name}}`, which is the only thing anyone ever
 *     wants from this page;
 *   - a clipped code block gets a Show more / Show less toggle.
 *
 * The toggle is rendered hidden and revealed here rather than guessed in PHP:
 * whether four lines of wrapped text overflow a 3-line clamp depends on the
 * column width, which only the browser knows.
 */
(function () {
    'use strict';

    function revealToggles(root) {
        (root || document).querySelectorAll('.erv-value').forEach(function (box) {
            var code = box.querySelector('.erv-code');
            var more = box.querySelector('.erv-more');
            if (!code || !more || box.classList.contains('is-open')) {
                return;
            }
            var clipped = code.scrollHeight > code.clientHeight + 2;
            // .is-clipped drives the bottom fade as well as the toggle: a block
            // that stops short of the clamp must not look cut off.
            box.classList.toggle('is-clipped', clipped);
            more.classList.toggle('d-none', !clipped);
        });
    }

    /*
     * The delegated listeners live on document, so a re-rendered index fragment
     * would stack a second copy of each and copy twice per click. Measuring, on
     * the other hand, has to run again on every render.
     */
    if (window.__ervListenersWired) {
        revealToggles();
        return;
    }
    window.__ervListenersWired = true;

    document.addEventListener('click', function (e) {
        var token = e.target.closest('.erv-token');
        if (token) {
            copyValueToClipboard(token.dataset.ervCopy, 'Variable copied to clipboard');
            return;
        }

        var more = e.target.closest('.erv-more');
        if (!more) {
            return;
        }
        var box = more.closest('.erv-value');
        var open = box.classList.toggle('is-open');
        more.querySelector('.erv-more-label').textContent = open ? 'Show less' : 'Show more';
    });

    // Space/Enter on a token, which is a <span role="button">.
    document.addEventListener('keydown', function (e) {
        if (e.key !== 'Enter' && e.key !== ' ') {
            return;
        }
        var token = e.target.closest('.erv-token');
        if (!token) {
            return;
        }
        e.preventDefault();
        copyValueToClipboard(token.dataset.ervCopy, 'Variable copied to clipboard');
    });

    document.addEventListener('DOMContentLoaded', function () { revealToggles(); });
    // The card view starts in a d-none container, so nothing in it has a height
    // to measure until the first switch.
    document.addEventListener('click', function (e) {
        if (e.target.closest('#viewList, #viewCard')) {
            window.setTimeout(revealToggles, 0);
        }
    });
    window.addEventListener('resize', function () { revealToggles(); });
    revealToggles();
}());
</script>
