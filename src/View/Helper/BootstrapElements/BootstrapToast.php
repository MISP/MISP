<?php

namespace App\View\Helper\BootstrapElements;

use App\View\Helper\BootstrapGeneric;

/**
 * Creates a bootstrap toast by calling creating a Toaster object and passing the provided options
 * 
 * # Options:
 * - text: The text content of the alert
 * - html: The HTML content of the alert
 * - dismissible: Can the alert be dissmissed
 * - variant: The Bootstrap variant of the alert
 * - fade: Should the alert fade when dismissed
 * - class: Additional classes to add to the alert container
 * 
 * # Usage:
 * $this->Bootstrap->toast([
 *     'title' => 'Title',
 *     'bodyHtml' => '<i>Body</i>',
 *     'muted' => 'Muted text',
 *     'variant' => 'warning',
 *     'closeButton' => true,
 * ]);
 */
class BootstrapToast extends BootstrapGeneric
{
    private $defaultOptions = [
        'id' => false,
        'title' => false,
        'muted' => false,
        'body' => false,
        'variant' => 'default',
        'autohide' => true,
        'delay' => 'auto',
        'titleHtml' => false,
        'mutedHtml' => false,
        'bodyHtml' => false,
        'closeButton' => true,
    ];

    function __construct(array $options)
    {
        $this->allowedOptionValues = [
            'variant' => array_merge(BootstrapGeneric::$variants, ['default']),
        ];
        $this->processOptions($options);
    }

    private function processOptions(array $options): void
    {
        $validOptions = array_filter($options, function($optionName) {
            return isset($this->defaultOptions[$optionName]);
        }, ARRAY_FILTER_USE_KEY);
        $this->options = array_merge($this->defaultOptions, $validOptions);
        $this->checkOptionValidity();
    }

    public function toast(): string
    {
        return $this->genToast();
    }

    private function genToast(): string
    {
        return $this->node('script', [], sprintf(
            "$(document).ready(function() {
                UI.toast(%s);
            })",
            json_encode($this->options, JSON_FORCE_OBJECT)
        ));
    }
}
