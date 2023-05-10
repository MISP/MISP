<?php
/*
     * Generic form builder
     *
     * Simply pass a JSON with the following keys set:
     * - model: The model used to create the form (such as Attribute, Event)
     * - fields: an array with each element generating an input field
     *     - field is the actual field name (such as org_id, name, etc) which is required
     *     - optional fields: default, type, options, placeholder, label - these are passed directly to $this->Form->input(),
     *     - requirements: boolean, if false is passed the field is skipped
     * - metafields: fields that are outside of the scope of the form itself
           - use these to define dynamic form fields, or anything that will feed into the regular fields via JS population
     * - submit: The submit button itself. By default it will simply submit to the form as defined via the 'model' field
     */
    $this->Form->setConfig('errorClass', 'is-invalid');
    $modelForForm = empty($data['model']) ?
        h(\Cake\Utility\Inflector::singularize(\Cake\Utility\Inflector::classify($this->request->getParam('controller')))) :
        h($data['model']);
    $entity = isset($entity) ? $entity : null;
    $fieldsString = '';
    $simpleFieldWhitelist = [
        'default', 'type', 'placeholder', 'label', 'empty', 'rows', 'div', 'required', 'templates', 'options', 'value', 'checked',
    ];
    if (empty($data['url'])) {
        $data['url'] = ["controller" => $this->request->getParam('controller'), "action" => $this->request->getParam('url')];
    }
    $formRandomValue = Cake\Utility\Security::randomString(8);
    $initSelect2 = false;
    $formCreate = $this->Form->create($entity, ['id' => 'form-' . $formRandomValue]);
    $default_template = [
        'inputContainer' => '<div class="row mb-3">{{content}}</div>',
        'inputContainerError' => '<div class="row mb-3 has-error">{{content}}</div>',
        'label' => '{{text}}',
        'input' => '<input type="{{type}}" name="{{name}}"{{attrs}} />',
        'textarea' => '<textarea name="{{name}}" {{attrs}}>{{value}}</textarea>',
        'select' => '<select name="{{name}}" {{attrs}}>{{content}}</select>',
        'checkbox' => '<input type="checkbox" name="{{name}}" value="{{value}}"{{attrs}}>',
        'checkboxFormGroup' => '{{label}}',
        'radio' => '<input type="radio" name="{{name}}" value="{{value}}"{{attrs}}>',
        'radioWrapper' => '{{label}}',
        'formGroup' => '<label class="col-sm-2 col-form-label form-label" {{attrs}}>{{label}}</label><div class="col-sm-10">{{input}}{{error}}</div>',
        'nestingLabel' => '{{hidden}}<div class="col-sm-2 form-label">{{text}}</div><div class="col-sm-10">{{input}}</div>',
        'option' => '<option value="{{value}}"{{attrs}}>{{text}}</option>',
        'optgroup' => '<optgroup label="{{label}}"{{attrs}}>{{content}}</optgroup>',
        'select' => '<select name="{{name}}"{{attrs}}>{{content}}</select>',
        'error' => '<div class="error-message invalid-feedback d-block">{{content}}</div>',
        'errorList' => '<ul>{{content}}</ul>',
        'errorItem' => '<li>{{text}}</li>',
    ];
    if (!empty($data['fields'])) {
        foreach ($data['fields'] as $fieldData) {
            if (!empty($fields)) {
                if (!in_array($fieldData['field'], $fields)) {
                    continue;
                }
            }
            $initSelect2 = $initSelect2 || (!empty($fieldData['type']) && $fieldData['type'] == 'dropdown' && !empty($fieldData['select2']));
            $formTemplate = $default_template;
            if (!empty($fieldData['floating-label'])) {
                $formTemplate['inputContainer'] = '<div class="form-floating input {{type}}{{required}}">{{content}}</div>';
                $formTemplate['label'] = '<label{{attrs}}>{{text}}</label>';
                $formTemplate['formGroup'] = '{{input}}{{label}}';
                $fieldData['placeholder'] = !empty($fieldData['label']) ? $fieldData['label'] : h($fieldData['field']);
            }
            if (!empty($data['templates'])) {
                $formTemplate = array_merge($formTemplate, $data['templates']);
            }
            // we reset the template each iteration as individual fields might override the defaults.
            $this->Form->setConfig($formTemplate);
            $this->Form->setTemplates($formTemplate);
            if (isset($fieldData['requirements']) && !$fieldData['requirements']) {
                continue;
            }
            $fieldsString .= $this->element(
                'genericElements/Form/fieldScaffold',
                [
                    'fieldData' => $fieldData,
                    'form' => $this->Form,
                    'simpleFieldWhitelist' => $simpleFieldWhitelist
                ]
            );
        }
    }
    $metaTemplateString = '';
    if (!empty($entity['MetaTemplates']) && count($entity['MetaTemplates']) > 0) {
        $metaTemplateString = $this->element(
            'genericElements/Form/metaTemplateScaffold',
            [
                'form' => $this->Form,
            ]
        );
    }
    $submitButtonData = ['model' => $modelForForm, 'formRandomValue' => $formRandomValue];
    if (!empty($data['submit'])) {
        $submitButtonData = array_merge($submitButtonData, $data['submit']);
    }
    if (!empty($data['ajaxSubmit'])) {
        $submitButtonData['ajaxSubmit'] = $ajaxSubmit;
    }
    $ajaxFlashMessage = '';
    if (!empty($ajax)) {
        $ajaxFlashMessage = sprintf(
            '<div id="flashContainer"><div id="main-view-container">%s</div></div>',
            $this->Flash->render()
        );
    }
    $formEnd = $this->Form->end();
    $actionName = h(\Cake\Utility\Inflector::humanize($this->request->getParam('action')));
    $modelName = h(\Cake\Utility\Inflector::humanize(\Cake\Utility\Inflector::singularize($this->request->getParam('controller'))));
    if (!empty($ajax)) {
        $seedModal = 'mseed-' . mt_rand();
        echo $this->Bootstrap->modal([
            'title' => empty($data['title']) ? sprintf('%s %s', $actionName, $modelName) : h($data['title']),
            'bodyHtml' =>  $this->element('genericElements/Form/formLayouts/formRaw', [
                'data' => $data,
                'formCreate' => $formCreate,
                'ajaxFlashMessage' => $ajaxFlashMessage,
                'fieldsString' => $fieldsString,
                'formEnd' => $formEnd,
                'metaTemplateString' => $metaTemplateString,
            ]),
            'size' => !empty($fieldsString) ? 'xl' : 'lg',
            'type' => 'confirm',
            'modalClass' => $seedModal,
        ]);
    } else if (!empty($raw)) {
        echo $this->element('genericElements/Form/formLayouts/formDefault', [
            'data' => $data,
            'actionName' => $actionName,
            'modelName' => $modelName,
            'submitButtonData' => $submitButtonData,
            'formCreate' => $formCreate,
            'ajaxFlashMessage' => $ajaxFlashMessage,
            'fieldsString' => $fieldsString,
            'formEnd' => $formEnd,
            'metaTemplateString' => $metaTemplateString,
        ]);
    } else {
        echo $this->element('genericElements/Form/formLayouts/formDefault', [
            'data' => $data,
            'actionName' => $actionName,
            'modelName' => $modelName,
            'submitButtonData' => $submitButtonData,
            'formCreate' => $formCreate,
            'ajaxFlashMessage' => $ajaxFlashMessage,
            'fieldsString' => $fieldsString,
            'formEnd' => $formEnd,
            'metaTemplateString' => $metaTemplateString,
        ]);
    }
?>
<script type="text/javascript">
    $(document).ready(function() {
        executeStateDependencyChecks();
        $('.formDropdown').on('change', function() {
            executeStateDependencyChecks('#' + this.id);
        })
    });
</script>