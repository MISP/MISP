<?php

namespace App\View\Helper\BootstrapElements;

use App\View\Helper\BootstrapGeneric;

/**
 * Creates a bootstrap modal based on the given options
 * 
 * # Options
 *  - size: Control the horizontal size of the modal. Valid values: 'sm', 'lg', 'xl'
 *  - centered, scrollable, backdropStatic: Default bootstrap behavior
 *  - show: Immediately instantiate the modal and show it
 *  - header-variant, body-variant, footer-variant: Default bootstrap variant to be applied to these modal sections
 *  - title: The title of the modal
 *  - titleHtml: The HTML title of the modal
 *  - body: The body of the modal
 *  - bodyHtml: The HTML body of the modal
 *  - footerHtml: The HTML footer of the modal. Override the $type option
 *  - dialogScrollable: Allows to scroll the modal body
 *  - modalClass, headerClass, footerClass: Classes to be applied to these modal sections
 *  - type: Control the type of actions available.
 *      Valid values: 'ok-only', 'confirm', 'custom'
 *      - The `ok-only` Displays a single 'Ok' button
 *      - The `confirm` Displays a 'Confirm' and 'Cancel' buttons
 *          - `confirmButton` and `cancelButton`: Can be used to pass a BootstrapElements/BootstrapButton configuration
 *      - The `custom` Display a list of button defined in the $footerButtons parameter
 *  - confirmFunction: The function to be called when clicking the "confirm" button
 *      - This options *only* works if the option $show is enabled or if the modal is loaded with the UI ModalFactory function (e.g. `UI.submissionModal()` or `UI.modal()`)
 *  - cancelOnclick: The function to be called once the "cancel" button trigger the `onclick` event
 *  - footerButtons: A list of configuration to be passed to BootstrapElements/BootstrapButton
 *      - The option `clickFunction` can be used to set the function to be called when clicking the button. Behavior similar to "confirmFunction"
 * 
 * # Click functions behaviors:
 *  - *-Onclick functions have the same behavior as the 'onclick' HTML parameter
 *  - `confirmFunction` and `clickFunction` are called with additional 2 additional arguments:
 *      - modalObject: The instantiated ModalFactory object
 *      - tmpApi: An instantiated AJAXApi object linked with the modal button
 *  - If no functions are provided, Submit the form in place or close the modal
 *
 *
 * # Usage:
 *
 * ## Simple styled modal that is displayed automatically when the HTML is attached to the page
 * $this->Bootstrap->modal([
 *    'title' => 'Modal title',
 *    'size' => 'lg',
 *    'type' => 'ok-only',
 *    'body' => '<b>Body content</b>',
 *    'header-variant' => 'dark',
 *    'body-variant' => 'light',
 *    'footer-variant' => 'warning',
 *    'show' => true,
 * ]);

 * ## Modal with custom onclick handler
 * $this->Bootstrap->modal([
 *     'type' => 'confirm',
 *     'bodyHtml' => '<b>Body content</b>',
 *     'confirmButton' => [
 *         'text' => 'Show modal',
 *         'icon' => 'eye',
 *         'onclick' => 'UI.toast({"title": "confirmed!"})',
 *     ],
 *     'cancelOnclick' => 'UI.toast({"title": "cancelled"})',
 *     'show' => true,
 * ]);
 * 
 * ## Modal with a onclick handler with prepared arguments bound to the confirm button
 * $this->Bootstrap->modal([
 *     'type' => 'confirm',
 *     'confirmButton' => [
 *         'text' => 'Confirm',
 *         'icon' => 'check',
 *     ],
 *     'confirmFunction' => 'myConfirmFunction', // myConfirmFunction is called with the $modalObject and $tmpApi intialized
 *     'show' => true,
 * ]);
 * 
 * /*
 * Example of confirm function
 *  - case 1: If void is returned the modal close automatically regardless of the result
 *  - case 2: If a promise is returned, the modal close automatically if the promise is a success
 *          A success is defined as follow:
 *              - No exceptions
 *              - No data returned 
 *              - Object returned with key `success` evaluting to true
 * - case 3: The modal can be closed manually with: `modalObject.hide()`
 * 
 * function myConfirmFunction(modalObject, tmpApi) {
 *     const $form = modalObject.$modal.find('form')
 *     const postPromise = $form.length == 1 ?
 *             tmpApi.postForm($form[0]) :
 *             tmpApi.fetchJSON('/users/view/', false, true)
 *         .then((result) => {
 *             console.log(result)
 *             constToReturn = {
 *                 success: true, // will close the modal automatically
 *             }
 *             return constToReturn
 *         })
 *         .catch((errors) => {
 *             console.log(errors)
 *         })
 * 
 *     return postPromise
 * }

 * ## Modal with custom footer made of buttons
 * $this->Bootstrap->modal([
 *     'type' => 'custom',
 *     'footerButtons' => [
 *         [
 *             'text' => 'Confirm',
 *             'icon' => 'check',
 *             'variant' => 'danger',
 *             'clickFunction' => 'testapi',
 *         ],
 *         [
 *             'text' => 'Cancel',
 *             'onclick' => 'UI.toast({"title": "confirmed!"})',
 *         ],
 *     ],
 *     'show' => true,
 * ]);
 */
class BootstrapModal extends BootstrapGeneric
{
    private $defaultOptions = [
        'size' => '',
        'centered' => true,
        'scrollable' => true,
        'backdropStatic' => false,
        'show' => false,
        'header-variant' => '',
        'body-variant' => '',
        'footer-variant' => '',
        'title' => '',
        'titleHtml' => null,
        'body' => '',
        'bodyHtml' => null,
        'footerHtml' => null,
        'dialogScrollable' => true,
        'modalClass' => [''],
        'headerClass' => [''],
        'bodyClass' => [''],
        'footerClass' => [''],
        'confirmButton' => [
            'text' => 'Confirm',
        ],
        'cancelButton' => [
            'text' => 'Cancel',
        ],
        'type' => 'ok-only',
        'footerButtons' => [],
        'confirmFunction' => '', // Will be called with the following arguments confirmFunction(modalObject, tmpApi)
        'cancelOnclick' => ''
    ];
    private $bsHelper;

    function __construct(array $options, $bsHelper)
    {
        $this->allowedOptionValues = [
            'size' => ['sm', 'lg', 'xl', ''],
            'type' => ['ok-only', 'confirm', 'cancel', 'custom'],
            'header-variant' =>  array_merge(BootstrapGeneric::$variants, ['']),
            'body-variant' =>  array_merge(BootstrapGeneric::$variants, ['']),
            'footer-variant' =>  array_merge(BootstrapGeneric::$variants, ['']),
        ];
        $this->processOptions($options);
        $this->bsHelper = $bsHelper;
    }

    private function processOptions(array $options): void
    {
        $this->options = array_merge($this->defaultOptions, $options);
        $this->checkOptionValidity();
        $this->options['modalClass'] = $this->convertToArrayIfNeeded($this->options['modalClass']);
        $this->options['headerClass'] = $this->convertToArrayIfNeeded($this->options['headerClass']);
        $this->options['bodyClass'] = $this->convertToArrayIfNeeded($this->options['bodyClass']);
        $this->options['footerClass'] = $this->convertToArrayIfNeeded($this->options['footerClass']);

        if (!empty($this->options['dialogScrollable'])) {
            $this->options['modalClass'][] = 'modal-dialog-scrollable';
        }

        $possiblVariants = ['header-variant', 'body-variant', 'footer-variant'];
        foreach ($possiblVariants as $possiblVariant) {
            if (!empty($this->options[$possiblVariant])) {
                $this->options[sprintf('%sClass', substr($possiblVariant, 0, -8))][] = self::getBGAndTextClassForVariant($this->options[$possiblVariant]);
            }
        }

        if (!empty($options['confirmFunction']) && !empty($options['confirmButton']['onclick'])) {
            throw new \InvalidArgumentException(__('Option `{0}` can not be used in conjuction with `{1}` for the confirm button', 'confirmFunction', 'onclick'));
        }
    }

    public function modal(): string
    {
        $modal = $this->genModal();
        if ($this->options['show']) {
            return $this->encapsulateWithUIHelper($modal);
        }
        return $modal;
    }

    private function encapsulateWithUIHelper(string $modal): string
    {
        return $this->node(
            'script',
            [],
            sprintf(
                "$(document).ready(function() {
                setTimeout(() => {
                    UI.modal({
                        rawHtml: \"%s\"
                    })
                }, 1);
            })",
                str_replace('"', '\"', $modal)
            )
        );
    }

    private function genModal(): string
    {
        $dialog = $this->nodeOpen(
            'div',
            [
            'class' => array_merge(
                ['modal-dialog', (!empty($this->options['size'])) ? "modal-{$this->options['size']}" : ''],
                $this->options['modalClass']
            ),
            ]
        );
        $content = $this->nodeOpen(
            'div',
            [
            'class' => ['modal-content'],
            ]
        );
        $header = $this->genHeader();
        $body = $this->genBody();
        $footer = $this->genFooter();
        $closedDiv = $this->nodeClose('div');

        $html = "{$dialog}{$content}{$header}{$body}{$footer}{$closedDiv}{$closedDiv}";
        return $html;
    }

    private function genHeader(): string
    {
        $header = $this->nodeOpen('div', ['class' => array_merge(['modal-header'], $this->options['headerClass'])]);
        $header .= $this->options['titleHtml'] ?? $this->node('h5', ['class' => ['modal-title']], h($this->options['title']));
        if (empty($this->options['backdropStatic'])) {
            $header .= $this->genericCloseButton('modal');
        }
        $header .= $this->nodeClose('div');
        return $header;
    }

    private function genBody(): string
    {
        $body = $this->nodeOpen('div', ['class' => array_merge(['modal-body'], $this->options['bodyClass'])]);
        $body .= $this->options['bodyHtml'] ?? h($this->options['body']);
        $body .= $this->nodeClose('div');
        return $body;
    }

    private function genFooter(): string
    {
        $footer = $this->nodeOpen(
            'div',
            [
            'class' => array_merge(['modal-footer'], $this->options['footerClass']),
            'data-custom-footer' => $this->options['type'] == 'custom'
            ]
        );
        $footer .= $this->options['footerHtml'] ?? $this->getFooterBasedOnType();
        $footer .= $this->nodeClose('div');
        return $footer;
    }

    private function getFooterBasedOnType(): string
    {
        if ($this->options['type'] == 'ok-only') {
            return $this->getFooterOkOnly();
        } else if (str_contains($this->options['type'], 'confirm')) {
            return $this->getFooterConfirm();
        } else if ($this->options['type'] == 'cancel') {
            return $this->getFooterCancel();
        } else if ($this->options['type'] == 'custom') {
            return $this->getFooterCustom();
        } else {
            return $this->getFooterOkOnly();
        }
    }

    private function getFooterOkOnly(): string
    {
        return (new BootstrapButton(
            [
            'variant' => 'primary',
            'text' => __('Ok'),
            'onclick' => $this->options['confirmOnclick'],
            'attrs' => [
                'data-bs-dismiss' => $this->options['confirmOnclick'] ?? 'modal',
            ],
            ],
            $this->bsHelper
        ))->button();
    }

    private function getFooterCancel(): string
    {
        return (new BootstrapButton(
            [
            'text' => __('Cancel'),
            'variant' => 'secondary',
            'attrs' => [
                'data-bs-dismiss' => 'modal',
            ]
            ],
            $this->bsHelper
        ))->button();
    }

    private function getFooterConfirm(): string
    {
        $buttonCancelConfig = array_merge(
            [
                'variant' => 'secondary',
                'attrs' => [
                    'data-bs-dismiss' => 'modal',
                    'onclick' => $this->options['cancelOnclick']
                ]
            ],
            $this->options['cancelButton'],
        );
        $buttonCancel = (new BootstrapButton($buttonCancelConfig, $this->bsHelper))->button();

        $defaultConfig = [
            'variant' => 'primary',
            'class' => 'modal-confirm-button',
        ];
        if (!empty($this->options['confirmOnclick'])) {
            $defaultConfig['onclick'] = $this->options['confirmOnclick'];
        }
        if (!empty($this->options['confirmFunction'])) {
            $defaultConfig['attrs']['data-confirmFunction'] = $this->options['confirmFunction'];
        }
        $buttonConfirmConfig = array_merge(
            $defaultConfig,
            $this->options['confirmButton'],
        );
        $buttonConfirm = (new BootstrapButton($buttonConfirmConfig, $this->bsHelper))->button();
        return $buttonCancel . $buttonConfirm;
    }

    private function getFooterCustom(): string
    {
        $buttons = [];
        foreach ($this->options['footerButtons'] as $buttonConfig) {
            $defaultConfig = [
                'variant' => 'primary',
                'class' => 'modal-confirm-button',
                'attrs' => [
                    'data-bs-dismiss' => !empty($buttonConfig['clickFunction']) ? '' : 'modal',
                ]
            ];
            if (!empty($buttonConfig['clickFunction'])) {
                $defaultConfig['attrs']['data-clickFunction'] = $buttonConfig['clickFunction'];
            }
            $buttonConfig = array_merge(
                $defaultConfig,
                $buttonConfig,
            );
            $buttons[] = (new BootstrapButton($buttonConfig, $this->bsHelper))->button();
        }
        return implode('', $buttons);
    }
}
