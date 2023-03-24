<?php

namespace App\View\Helper\BootstrapElements;

use App\View\Helper\BootstrapGeneric;

/**
 * Creates a bootstrap progress bar
 * 
 * # Options:
 *  - label: A text to be centered in the active part of the progress bar. If set to `true`, will display the percentage of the progress bar
 *  - title: The title HTML attribute to set
 *  - total: The total amount of the progress
 *  - value: The active part of the progress
 *  - variant: The bootstrap variant of the active part of the progress bar
 *  - height: The height of the bar
 *  - striped, animated: If the bar should have the striped and animated bootstrap properties
 *  - attrs: Additional HTML attributes to add
 * 
 * # Usage:
 * $this->Bootstrap->progress([
 *     'value' => 45,
 *     'total' => 100,
 *     'label' => true,
 * ]);
 * 
 */
class BootstrapProgress extends BootstrapGeneric
{
    private $defaultOptions = [
        'value' => 0,
        'total' => 100,
        'label' => true,
        'title' => '',
        'variant' => 'primary',
        'height' => '',
        'striped' => false,
        'animated' => false,
        'attrs' => [],
    ];

    function __construct($options)
    {
        $this->allowedOptionValues = [
            'variant' => BootstrapGeneric::$variants,
        ];
        $this->processOptions($options);
    }

    private function processOptions($options): void
    {
        $this->options = array_merge($this->defaultOptions, $options);
        $this->checkOptionValidity();
    }

    public function progress(): string
    {
        return $this->genProgress();
    }

    private function genProgress(): string
    {
        $percentage = round(100 * $this->options['value'] / $this->options['total']);
        $heightStyle = !empty($this->options['height']) ? sprintf('height: %s;', h($this->options['height'])) : '';
        $widthStyle = sprintf('width: %s%%;', $percentage);
        $label = !empty($this->options['label']) ? ($this->options['label'] === true ? "{$percentage}%" : h($this->options['label'])) : '';
        $pb = $this->node('div', array_merge([
            'class' => [
                'progress-bar',
                "bg-{$this->options['variant']}",
                $this->options['striped'] ? 'progress-bar-striped' : '',
                $this->options['animated'] ? 'progress-bar-animated' : '',
            ],
            'role' => "progressbar",
            'aria-valuemin' => "0", 'aria-valuemax' => "100", 'aria-valuenow' => $percentage,
            'style' => $widthStyle,
            'title' => h($this->options['title']),
        ], $this->options['attrs']), $label);
        $container = $this->node('div', [
            'class' => [
                'progress',
            ],
            'style' => $heightStyle,
            'title' => h($this->options['title']),
        ], $pb);
        return $container;
    }
}
