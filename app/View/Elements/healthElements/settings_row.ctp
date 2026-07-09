<?php
    if ($setting['setting'] !== 'Security.salt') {
        $bgColour = '';
        $colour_coding = array(
            0 => 'error',
            1 => 'warning',
            2 => 'success',
            3 => 'info'
        );
        if ($setting['type'] === 'boolean') {
            $setting['value'] = $setting['value'] === true ? 'true' : 'false';
        }
        if (isset($setting['options'])) {
            $setting['value'] = empty($setting['options'][$setting['value']]) ? null : $setting['options'][$setting['value']];
        }
        if (!empty($setting['redacted'])) {
            $setting['value'] = '*****';
        }
        // Expose the hidden behavioural "posture" of each setting (#10812) as small
        // badges next to the setting name, so admins can see at a glance which
        // settings are CLI-only, stored in the config file for security, redacted
        // in the UI, or not editable from the web interface. These properties
        // already travel with each setting row; previously only `cli_only` was
        // hinted at (as inline text in the description) and the rest were invisible.
        $posture = array();
        if (!empty($setting['cli_only'])) {
            $posture[] = array(
                'class' => 'label-important',
                'text'  => __('CLI only'),
                'title' => __('This setting can only be changed from the command line.')
            );
        }
        if (!empty($setting['file_only'])) {
            $posture[] = array(
                'class' => 'label-inverse',
                'text'  => __('File only'),
                'title' => __('For security reasons this setting is always stored in the config file, never in the database.')
            );
        }
        if (!empty($setting['redacted'])) {
            $posture[] = array(
                'class' => 'label-warning',
                'text'  => __('Redacted'),
                'title' => __('The value of this setting is hidden in the UI.')
            );
        }
        if (isset($setting['editable']) && !$setting['editable']) {
            $posture[] = array(
                'class' => 'label',
                'text'  => __('Read only'),
                'title' => __('This setting cannot be edited from the UI.')
            );
        }
        $postureBadges = '';
        foreach ($posture as $flag) {
            $postureBadges .= sprintf(
                ' <span class="label %s" title="%s">%s</span>',
                h($flag['class']),
                h($flag['title']),
                h($flag['text'])
            );
        }
        $column_data = array(
            'level' => array(
                'html' => $priorities[$setting['level']],
                'class' => 'short live_filter_target'
            ),
            'setting' => array(
                'html' => (empty($setting['cli_only']) ?
                    sprintf('%s<span %s></span>',
                        h($setting['setting']),
                        sprintf('role="button" tabindex="0" aria-label="%s" aria-controls="setting_%s_%s_placeholder" onclick="serverSettingsActivateField(\'%s\',\'%s\');"',
                            h('edit'),
                            h($subGroup), h($k),
                            h($setting['setting']), h($k)))
                    : h($setting['setting'])) . $postureBadges,
                'class' => 'short live_filter_target',
                'ondblclick' => 'serverSettingsActivateField',
                'ondblclickParams' => array(h($setting['setting']), h($k))
            ),
            'value_passive' => array(
                'html' => nl2br(h($setting['value'])),
                'class' => 'inline-field-solid live_filter_target',
                'requirement' => ((isset($setting['editable']) && !$setting['editable']) || !empty($setting['cli_only'])),
                'style' => 'width:500px;',
                'id' => sprintf(
                    'setting_%s_%s_passive',
                    h($subGroup),
                    h($k)
                )
            ),
            'value_solid' => array(
                'html' => nl2br(h($setting['value'])),
                'class' => 'inline-field-solid live_filter_target',
                'requirement' => ((!isset($setting['editable']) || $setting['editable']) && empty($setting['cli_only'])),
                'style' => 'width:500px;',
                'id' => sprintf(
                    'setting_%s_%s_solid',
                    h($subGroup),
                    h($k)
                ),
                'ondblclick' => 'serverSettingsActivateField',
                'ondblclickParams' => array(h($setting['setting']), h($k))
            ),
            'value_placeholder' => array(
                'class' => 'inline-field-placeholder hidden',
                'requirement' => ((!isset($setting['editable']) || $setting['editable']) && empty($setting['cli_only'])),
                'style' => 'width:500px;',
                'id' => sprintf(
                    'setting_%s_%s_placeholder',
                    h($subGroup),
                    h($k)
                )
            ),
            'description' => array(
                'html' => $setting['description'],
                'class' => 'live_filter_target'
            ),
            'error' => array(
                'html' => isset($setting['errorMessage']) ? h($setting['errorMessage']) : ''
            )
        );
        $columns = '';
        foreach ($column_data as $field => $data) {
            if (!isset($data['requirement']) || $data['requirement']) {
                $columns .= sprintf(
                    '<td %s class="%s" %s %s>%s</td>',
                    empty($data['id']) ? '' : sprintf('id="%s"', h($data['id'])),
                    empty($data['class']) ? '' : h($data['class']),
                    empty($data['style']) ? '' : sprintf('style="%s"', h($data['class'])),
                    empty($data['ondblclick']) ? '' : sprintf(
                        'ondblclick="%s(%s)"',
                        h($data['ondblclick']),
                        empty($data['ondblclickParams']) ? '' : sprintf("'%s'", implode("','", $data['ondblclickParams']))
                    ),
                    empty($data['html']) ? '' : $data['html']
                );
            }
        }
        echo sprintf(
            '<tr id="%s" class="subGroup_%s %s">%s</tr>',
            sprintf(
                '%s_%s_row',
                h($subGroup),
                h($k)
            ),
            h($subGroup),
            !empty($setting['error']) ? $colour_coding[$setting['level']] : '',
            $columns
        );
    }

