<?php

$count = count($idArray);
$message = $count > 1
    ? __('Are you sure you want to delete %s event templates?', $count)
    : __('Are you sure you want to delete event template #%s?', h($idArray[0]));

$libraryManaged = (int)($libraryManaged ?? 0);
$warning = null;
if ($libraryManaged > 0) {
    $warning = $libraryManaged === $count
        ? __n(
            'This template is managed by the misp-event-templates library — the next "Update from library" run will re-import it. Uncheck Library-managed in the builder first to keep it deleted.',
            'These templates are managed by the misp-event-templates library — the next "Update from library" run will re-import them. Uncheck Library-managed in the builder first to keep them deleted.',
            $count,
            $count
        )
        : __n(
            '%s of them is managed by the misp-event-templates library and will be re-imported by the next "Update from library" run.',
            '%s of them are managed by the misp-event-templates library and will be re-imported by the next "Update from library" run.',
            $libraryManaged,
            $libraryManaged
        );
}

echo $this->element('genericElementsBS5/Forms/confirmationForm', [
    'title' => __('Event Template Deletion'),
    'model' => 'EventTemplate',
    'url' => $baseurl . '/event_templates/deleteSelection',
    'message' => $message,
    'submitLabel' => $count > 1 ? __('Delete templates') : __('Delete template'),
    'submitClass' => 'btn btn-danger',
    'submitIcon' => 'trash',
    'warning' => $warning,
]);
