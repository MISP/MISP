<?php
$random = Cake\Utility\Security::randomString(8);
$params['div'] = false;

$genUUIDButton = $this->Bootstrap->button([
    'id' => "uuid-gen-{$random}",
    'variant' => 'secondary',
    'text' => __('Generate'),
]);

$this->Form->setTemplates([
    'input' => sprintf('<div class="input-group">%s{{genUUIDButton}}</div>', $this->Form->getTemplates('input')),
]);
$params['templateVars'] = [
    'genUUIDButton' => $genUUIDButton,
];

$formElement = $this->FormFieldMassage->prepareFormElement($this->Form, $params, $fieldData);
echo $formElement;
?>
<script type="text/javascript">
    $(document).ready(function() {
        const $node = $('#uuid-gen-<?= h($random) ?>')
        $node.click(fetchUUID)

        function fetchUUID() {
            const urlGet = '/organisations/generateUUID'
            const options = {
                statusNode: $node,
            }
            return AJAXApi.quickFetchJSON(urlGet, options)
                .then(function(data) {
                    $('#uuid-field').val(data["uuid"])
                })
                .catch((e) => {
                    UI.toast({
                        variant: 'danger',
                        text: '<?= __('Could not generate UUID') ?>'
                    })
                })
        }
    });
</script>