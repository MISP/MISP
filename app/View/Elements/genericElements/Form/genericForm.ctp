<?php
    /*
     * Generic form builder
     *
     * Simply pass a JSON with the following keys set:
     * - model: The model used to create the form (such as Attribute, Event)
     * - description: text description of the form
     * - fields: an array with each element generating an input field
     *     - field is the actual field name (such as org_id, name, etc) which is required
     *     - optional fields: default, type, options, placeholder, label - these are passed directly to $this->Form->input(),
     *     - requirements: boolean, if false is passed the field is skipped
     * - metafields: fields that are outside of the scope of the form itself
           - use these to define dynamic form fields, or anything that will feed into the regular fields via JS population
     * - submit: The submit button itself. By default it will simply submit to the form as defined via the 'model' field
     */
    $modelForForm = empty($data['model']) ?
        h(Inflector::singularize(Inflector::classify($this->request->params['controller']))) :
        h($data['model']);
    $fieldsString = '';
    $simpleFieldAllowedlist = array(
        'default', 'type', 'options', 'placeholder', 'label', 'empty', 'rows', 'div', 'required', 'checked', 'multiple', 'selected', 'legend',
        'disabled',
    );
    $fieldsArrayForPersistence = array();
    $formOptions = isset($formOptions) ? $formOptions : array();
    $formOptions = array_merge(['class' => 'genericForm'], $formOptions);
    $formCreate = $this->Form->create($modelForForm, $formOptions);
    if (!empty($data['fields'])) {
        foreach ($data['fields'] as $fieldData) {
            if (isset($fieldData['requirements']) && !$fieldData['requirements']) {
                continue;
            }
            if (is_array($fieldData)) {
                if (empty($fieldData['label'])) {
                    $fieldData['label'] = Inflector::humanize($fieldData['field']);
                }
                if (!empty($fieldDesc[$fieldData['field']])) {
                    $fieldData['label'] .= $this->element(
                        'genericElements/Form/formInfo', array(
                            'field' => $fieldData,
                            'fieldDesc' => $fieldDesc[$fieldData['field']],
                            'modelForForm' => $modelForForm
                        )
                    );
                }
                $params = array();
                if (!empty($fieldData['class'])) {
                    if (is_array($fieldData['class'])) {
                        $class = implode(' ', $fieldData['class']);
                    } else {
                        $class = $fieldData['class'];
                    }
                    $params['class'] = $class;
                } else {
                    if (!empty($fieldData['type']) && ($fieldData['type'] !== 'checkbox' && $fieldData['type'] !== 'radio')) {
                        $params['class'] = 'span6';
                    }
                }
                foreach ($simpleFieldAllowedlist as $f) {
                    if (!empty($fieldData[$f])) {
                        $params[$f] = $fieldData[$f];
                    }
                }
                if (!empty($fieldData['picker']) && isset($fieldData['picker']['function'])) {
                    $fieldData['picker']['text'] = isset($fieldData['picker']['text']) ? $fieldData['picker']['text'] : __('Picker');
                    $params['div'] = 'input text input-append';
                    $params['after'] = sprintf('<button type="button" class="btn" onclick="%s.call(this);">%s</button>', $fieldData['picker']['function'], __($fieldData['picker']['text']));
                }
                if (!empty($params['type']) && $params['type'] === 'dropdown') {
                    $params['type'] = 'select';
                }
                if (!empty($fieldData['description'])) {
                    if (!isset($params['class'])) {
                        $params['class'] = '';
                    }
                    $params['class'] .= ' input-with-description';
                }
                $temp = $this->Form->input($fieldData['field'], $params);
                if (!empty($fieldData['description'])) {
                    $temp .= sprintf('<small class="clear form-field-description apply_css_arrow">%s</small>', h($fieldData['description']));
                }
                $fieldsArrayForPersistence []= $modelForForm . Inflector::camelize($fieldData['field']);
                if (!empty($fieldData['hidden'])) {
                    $temp = '<span class="hidden">' . $temp . '</span>';
                }
                $fieldsString .= $temp;
            } else {
                $fieldsString .= $fieldData;
            }
            if (empty($fieldData['stayInLine'])) {
                $fieldsString .= '<div class="clear"></div>';
            }
        }
    }
    $metaFieldString = '';
    if (!empty($data['metaFields'])) {
        foreach ($data['metaFields'] as $metaField) {
            $metaFieldString .= $metaField;
        }
    }
    $submitButtonData = array('model' => $modelForForm);
    if (!empty($data['submit'])) {
        $submitButtonData = array_merge($submitButtonData, $data['submit']);
    }
    if (!empty($data['ajaxSubmit'])) {
        $submitButtonData['ajaxSubmit'] = $ajaxSubmit;
    }
    $ajaxFlashMessage = '';
    if ($ajax) {
        $ajaxFlashMessage = sprintf(
            '<div id="flashContainer"><div id="main-view-container">%s</div></div>',
            $this->Flash->render()
        );
    }
    $formEnd = $this->Form->end();
    if (!empty($ajax)) {
        echo sprintf(
            '<div id="genericModal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="genericModalLabel" aria-hidden="true">%s%s%s</div>',
            sprintf(
                '<div class="modal-header"><button type="button" class="close" data-dismiss="modal" aria-hidden="true">×</button><h3 id="genericModalLabel">%s</h3></div>',
                empty($data['title']) ? h(Inflector::humanize($this->request->params['action'])) . ' ' . $modelForForm : h($data['title'])
            ),
            sprintf(
                '<div class="modal-body modal-body-long">%s</div>',
                sprintf(
                    '%s%s<fieldset>%s%s</fieldset>%s%s',
                    empty($data['description']) ? '' : $data['description'],
                    $formCreate,
                    $ajaxFlashMessage,
                    $fieldsString,
                    $formEnd,
                    $metaFieldString
                )
            ),
            sprintf(
                '<div class="modal-footer">%s</div>',
                $this->element('genericElements/Form/submitButton', $submitButtonData)
            )
        );
    } else {
        echo sprintf(
            '<div class="%s">%s<fieldset><legend>%s</legend>%s<div class="clear">%s</div>%s</fieldset>%s%s%s</div>',
            empty($data['skip_side_menu']) ? 'form' : 'menuless-form',
            $formCreate,
            empty($data['title']) ? h(Inflector::humanize($this->request->params['action'])) . ' ' . $modelForForm : h($data['title']),
            $ajaxFlashMessage,
            empty($data['description']) ? '' : $data['description'],
            $fieldsString,
            $formEnd,
            $metaFieldString,
            $this->element('genericElements/Form/submitButton', $submitButtonData)
        );
    }
?>
<script type="text/javascript">
    var fieldsArray = <?php echo json_encode($fieldsArrayForPersistence); ?>;
    $(function() {
        popoverStartup();
    });
</script>
