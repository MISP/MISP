<?php

namespace App\View\Helper\BootstrapElements;

use App\View\Helper\BootstrapGeneric;

/**
 * Creates a switch acting as a checkbox
 * 
 * # Options:
 * - label: The label associated with the switch
 * - disabled: Should the switch be disabled
 * - checked: Should the switch be checked by default
 * - title: Optional title to add to the switch
 * - variant: The variant to use to show if the switch is active
 * - class: Additional class to add to the switch
 * - attrs: Additional HTML attributes to add to the switch
 * 
 * # Usage:
 * $this->Bootstrap->switch([
 *     'label' => 'my label',
 *     'checked' => true,
 * ]); 
 */
class BootstrapSwitch extends BootstrapGeneric
{
    private $defaultOptions = [
        'label' => '',
        'variant' => 'primary',
        'disabled' => false,
        'checked' => false,
        'title' => '',
        'class' => [],
        'attrs' => [],
    ];

    public function __construct(array $options)
    {
        $this->allowedOptionValues = [
            'variant' => BootstrapGeneric::$variants,
        ];
        $this->processOptions($options);
    }

    private function processOptions(array $options): void
    {
        $this->options = array_merge($this->defaultOptions, $options);
        $this->checkOptionValidity();
    }

    public function switch(): string
    {
        return $this->genSwitch();
    }

    public function genSwitch(): string
    {
        $tmpId = 'tmp-' . mt_rand();
        $input = self::node('input', array_merge(
            [
                'type' => "checkbox",
                'class' => 'form-check-input',
                'id' => $tmpId,
                'disabled' => !empty($this->options['disabled']),
                'checked' => !empty($this->options['checked']),
            ],
            $this->options['attrs']
        ));
        $label = self::node('label', [
            'class' => 'form-check-label',
            'for' => $tmpId,
        ], h($this->options['label']));
        $html = self::node('div', [
            'class' => [
                'form-check form-switch',
            ],
            'title' => h($this->options['title']),
        ], [$input, $label]);
        return $html;
    }
}