<?php
/**
 * Beta UI — Add element to Collection form
 *
 * Improved version of the default add_element_to_collection form:
 * - Shows what is being added at the top
 * - Collection dropdown with "create new collection" link
 * - Description textarea
 *
 * @since 2.5.x (beta)
 */
$currentElementType = !empty($this->request->params['pass'][0]) ? $this->request->params['pass'][0] : 'Event';
$currentElementUuid = !empty($this->request->params['pass'][1]) ? $this->request->params['pass'][1] : '';
$selectedElementUuids = !empty($this->request->data['CollectionElement']['element_uuid'])
    ? (array)$this->request->data['CollectionElement']['element_uuid']
    : [$currentElementUuid];
$selectedElementUuids = array_values(array_filter(array_map('trim', $selectedElementUuids), function ($uuid) {
    return $uuid !== '';
}));
$selectedElementCount = count($selectedElementUuids);
$canCreateCollection = $this->Acl->canAccess('collections', 'add');
$createCollectionOptionValue = '__create_new_collection__';
$collectionOptions = $dropdownData['collections'];
asort($collectionOptions, SORT_NATURAL | SORT_FLAG_CASE);
if ($canCreateCollection) {
    $collectionOptions[$createCollectionOptionValue] = __('Create new collection...');
}
?>

<?php
// Render the standard generic form which handles the POST correctly
$fields = [
        [
            'field' => 'collection_id',
            'class' => 'input span6',
            'options' => $collectionOptions,
            'type' => 'dropdown',
            'label' => __('Collection')
        ],
        [
            'field' => 'description',
            'class' => 'span6',
            'type' => 'textarea',
            'label' => __('Analyst Note (optional)'),
            'placeholder' => __('Why is this event relevant to the collection?')
        ]
];

$description = sprintf(
    '<div class="beta-modal-header-info">'
    . '<i class="fa fa-folder-plus fa-2x" style="color:#428bca; margin-right:10px; vertical-align:middle;"></i>'
    . '<div style="display:inline-block; vertical-align:middle;">'
    . '<strong>%s</strong><br>'
    . '<small style="color:#888;">%s%s</small>'
    . '</div>'
    . '</div>'
    . '<hr style="margin: 12px 0;">',
    __('Add to Collection'),
    h($currentElementType),
    $selectedElementCount > 1
        ? ' &mdash; <strong>' . h(__n('%s selected event', '%s selected events', $selectedElementCount, $selectedElementCount)) . '</strong>'
        : (!empty($currentElementUuid) ? ' &mdash; <code style="font-size:11px;">' . h(substr($currentElementUuid, 0, 12)) . '…</code>' : '')
);

$metaFields = [];
if ($selectedElementCount > 1) {
    foreach ($selectedElementUuids as $selectedElementUuid) {
        $metaFields[] = sprintf(
            '<input type="hidden" name="data[CollectionElement][element_uuid][]" value="%s">',
            h($selectedElementUuid)
        );
    }
}
if ($canCreateCollection) {
    $createCollectionQuery = http_build_query([
        'attach_element_type' => $currentElementType,
        'attach_element_uuid' => $selectedElementUuids,
    ]);
    $createCollectionUrl = sprintf(
        '%s/collections/add?%s',
        h($baseurl),
        $createCollectionQuery
    );
}

echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'description' => $description,
        'model' => 'CollectionElement',
        'title' => false,
        'fields' => $fields,
        'metaFields' => $metaFields,
        'submit' => [
            'action' => $this->request->params['action'],
            'ajaxSubmit' => 'submitAddElementToCollectionBeta();'
        ]
    ]
]);
?>

<script>
<?php if ($canCreateCollection): ?>
$(document)
    .off('focus.betaCollectionCreateOption', '#genericModal select[name="data[CollectionElement][collection_id]"]')
    .on('focus.betaCollectionCreateOption', '#genericModal select[name="data[CollectionElement][collection_id]"]', function() {
        $(this).data('betaPrevValue', $(this).val());
    })
    .off('change.betaCollectionCreateOption', '#genericModal select[name="data[CollectionElement][collection_id]"]')
    .on('change.betaCollectionCreateOption', '#genericModal select[name="data[CollectionElement][collection_id]"]', function() {
        var createValue = <?php echo json_encode($createCollectionOptionValue); ?>;
        if ($(this).val() !== createValue) {
            $(this).data('betaPrevValue', $(this).val());
            return;
        }

        var prevValue = $(this).data('betaPrevValue');
        if (prevValue && prevValue !== createValue) {
            $(this).val(prevValue);
        } else if (this.options.length > 0) {
            this.selectedIndex = 0;
        }

        openGenericModal(<?php echo json_encode($createCollectionUrl); ?>);
    });
<?php endif; ?>

function normalizeCollectionModalMessage(message, fallback) {
    if (typeof message === 'string') {
        return message;
    }
    if (Array.isArray(message)) {
        return message.join(', ');
    }
    if (message && typeof message === 'object') {
        try {
            return Object.values(message).flat().join(', ');
        } catch (e) {
            return fallback;
        }
    }
    return fallback;
}

function getCollectionModalForm() {
    var $genericForm = $('#genericModal .genericForm');
    return $genericForm.length ? $genericForm : $('.genericForm').first();
}

function getEventCollectionContextUuids() {
    var context = window.eventCollectionContext;
    if (!context || !Array.isArray(context.eventUuids)) {
        return [];
    }
    return context.eventUuids.filter(function(uuid) {
        return typeof uuid === 'string' && uuid.length > 0;
    });
}

function syncEventCollectionContextForm($form) {
    var selectedEventUuids = getEventCollectionContextUuids();
    if (!selectedEventUuids.length) {
        return;
    }

    if (typeof window.syncSelectedEventCollectionFields === 'function') {
        window.syncSelectedEventCollectionFields($form, selectedEventUuids);
        return;
    }

    $form.find('input[name="data[CollectionElement][element_uuid][]"]').remove();
    selectedEventUuids.forEach(function(eventUuid) {
        $('<input>', {
            type: 'hidden',
            name: 'data[CollectionElement][element_uuid][]',
            value: eventUuid
        }).appendTo($form);
    });
}

function parseCollectionModalResponse(data) {
    if (typeof data !== 'string') {
        return data;
    }
    try {
        return JSON.parse(data);
    } catch (e) {
        return null;
    }
}

function submitAddElementToCollectionBeta() {
    var $genericForm = getCollectionModalForm();
    syncEventCollectionContextForm($genericForm);

    $.ajax({
        type: 'POST',
        url: $genericForm.attr('action'),
        data: $genericForm.serialize(),
        headers: { Accept: 'application/json' },
        success: function(data) {
            var response = parseCollectionModalResponse(data);

            if (response && response.saved) {
                showMessage('success', normalizeCollectionModalMessage(response.success || response.message, 'Element added to the Collection.'));
                $('#genericModal').modal('hide').remove();
                if (typeof window.loadEventCollections === 'function') {
                    window.loadEventCollections(true);
                }
                return;
            }

            if (response) {
                showMessage('fail', normalizeCollectionModalMessage(response.errors || response.error || response.message, 'Element could not be added to the Collection.'));
                return;
            }

            showMessage('fail', 'Could not complete the requested action.');
        },
        error: xhrFailCallback
    });
}
</script>
