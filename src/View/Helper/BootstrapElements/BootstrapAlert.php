<?php

namespace App\View\Helper\BootstrapElements;

use App\View\Helper\BootstrapGeneric;

/**
 * Creates a bootstrap alert
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
 * $this->Bootstrap->alert([
 *     'text' => 'This is an alert',
 *     'dismissible' => false,
 *     'variant' => 'warning',
 *     'fade' => false,
 * ]);
 */
class BootstrapAlert extends BootstrapGeneric
{
    private $defaultOptions = [
        'text' => '',
        'html' => null,
        'dismissible' => true,
        'variant' => 'primary',
        'fade' => true,
        'class' => [],
    ];

    function __construct(array $options)
    {
        $this->allowedOptionValues = [
            'variant' => BootstrapGeneric::$variants,
        ];
        $this->processOptions($options);
    }

    private function processOptions(array $options): void
    {
        $this->options = array_merge($this->defaultOptions, $options);
        $this->options['class'] = $this->convertToArrayIfNeeded($this->options['class']);
        $this->checkOptionValidity();
    }

    public function alert(): string
    {
        return $this->genAlert();
    }

    private function genAlert(): string
    {
        $html = $this->nodeOpen('div', [
            'class' => array_merge([
                'alert',
                "alert-{$this->options['variant']}",
                $this->options['dismissible'] ? 'alert-dismissible' : '',
                $this->options['fade'] ? 'fade show' : '',
            ], $this->options['class']),
            'role' => "alert"
        ]);

        $html .= $this->options['html'] ?? h($this->options['text']);
        $html .= $this->genCloseButton();
        $html .= $this->nodeClose('div');
        return $html;
    }

    private function genCloseButton(): string
    {
        $html = '';
        if ($this->options['dismissible']) {
            $html .= $this->genericCloseButton('alert');
        }
        return $html;
    }
}
