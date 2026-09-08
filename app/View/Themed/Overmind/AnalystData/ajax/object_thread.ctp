<?php
/*
 * Modal fragment: the analyst-data thread attached to a given MISP object,
 * opened via openModal from the analyst-data count badges in the index tables.
 * Delegates to the shared Elements/AnalystData/thread renderer with the modal
 * header enabled (the full-page analystData/view reuses the same renderer
 * without the header).
 */
echo $this->element('AnalystData/thread', [
    'analystData'     => $analystData,
    'objectType'      => $objectType,
    'objectUuid'      => $objectUuid,
    'showModalHeader' => true,
]);
