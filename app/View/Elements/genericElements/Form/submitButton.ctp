<?php
    if ($ajax) {
        $submit = isset($ajaxSubmit) ? $ajaxSubmit : '$(\'.genericForm\').submit();';
        echo sprintf(
            '%s%s',
            sprintf(
                '<button id="submitButton" class="btn btn-primary" onClick="%s">%s</button>',
                $submit,
                __('Submit')
            ),
            sprintf(
                '<button class="btn" data-dismiss="modal" aria-hidden="true" onClick="%s">%s</button>',
                'cancelPopoverForm();',
                __('Cancel')
            )
        );
    } else {
        if (!empty($submitFunction)) {
            $submitAction = $submitFunction;
        } else {
            $submitAction = sprintf(
                "$('#%s%sForm').submit();",
                h($model),
                h(Inflector::classify($action))
            );
        }
        echo sprintf(
            '<button onClick="%s" class="btn btn-%s">%s</button>',
            $submitAction,
            empty($type) ? 'primary' : h($type),
            empty($text) ? __('Submit') : h($text)
        );
    }
