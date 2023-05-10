<?php

namespace App\View\Helper\BootstrapElements;

use App\View\Helper\BootstrapGeneric;

/**
 * Creates a progress timeline similar to a form wizard
 * 
 * # Options:
 *  - variant: The variant of the active part of the timeline
 *  - variantInactive: The variant of the inactive part of the timeline
 *  - selected: 0-indexed step number to be selected. Will make all steps before the selected step active
 *  - steps: The definition of the step. Options are:
 *      - text: The text of the step
 *      - icon: The icon of the step. Default to the text number if empty
 *      - title: A title to be set for the step
 * 
 * # Usage:
 * $this->Bootstrap->progressTimeline([
 *     'selected' => 1,
 *     'steps' => [
 *         [
 *             'text' => __('Step 1'),
 *             'icon' => 'star',
 *             'title' => __('Title'),
 *         ],
 *         [
 *             'text' => __('Step 3'),
 *             'icon' => 'exchange-alt',
 *         ]
 *     ],
 * ]);
 */
class BootstrapProgressTimeline extends BootstrapGeneric
{
    private $defaultOptions = [
        'steps' => [],
        'selected' => 0,
        'variant' => 'primary',
        'variantInactive' => 'secondary',
    ];

    function __construct($options, $btHelper)
    {
        $this->allowedOptionValues = [
            'variant' => BootstrapGeneric::$variants,
            'variantInactive' => BootstrapGeneric::$variants,
        ];
        $this->processOptions($options);
        $this->btHelper = $btHelper;
    }

    private function processOptions($options): void
    {
        $this->options = array_merge($this->defaultOptions, $options);
        $this->checkOptionValidity();
    }

    public function progressTimeline(): string
    {
        return $this->genProgressTimeline();
    }

    private function getStepIcon(array $step, int $i, bool $nodeActive, bool $lineActive): string
    {
        $icon = $this->node('b', [
            'class' => [
                !empty($step['icon']) ? h($this->btHelper->FontAwesome->getClass($step['icon'])) : '',
                $this->getTextClassForVariant($this->options['variant'])
            ],
        ], empty($step['icon']) ? h($i + 1) : '');

        $containerDefaultClass = [
            'd-flex',
            'align-items-center',
            'justify-content-center',
            'rounded-circle',
        ];
        $containerDefaultClass[] = $nodeActive ? "bg-{$this->options['variant']}" : "bg-{$this->options['variantInactive']}";
        $iconContainer = $this->node('span', [
            'class' => $containerDefaultClass,
            'style' => 'width:50px; height:50px'
        ], $icon);
        $li = $this->node('li', [
            'class' => [
                'd-flex', 'flex-column',
                $nodeActive ? 'progress-active' : 'progress-inactive',
            ],
        ], $iconContainer);
        $html = $li . $this->getHorizontalLine($i, $nodeActive, $lineActive);
        return $html;
    }

    private function getHorizontalLine(int $i, bool $nodeActive, bool $lineActive): string
    {
        $stepCount = count($this->options['steps']);
        if ($i == $stepCount - 1) {
            return '';
        }
        $progressBar = (new BootstrapProgress([
            'label' => false,
            'value' => $nodeActive ? ($lineActive ? 100 : 50) : 0,
            'height' => '2px',
            'variant' => $this->options['variant']
        ]))->progress();
        $line = $this->node('span', [
            'class' => [
                'progress-line',
                'flex-grow-1', 'align-self-center',
                $lineActive ? "bg-{$this->options['variant']}" : ''
            ],
        ], $progressBar);
        return $line;
    }

    private function getStepText(array $step, bool $isActive): string
    {
        return $this->node('li', [
            'class' => [
                'text-center',
                'fw-bold',
                $isActive ? 'progress-active' : 'progress-inactive',
            ],
        ], h($step['text'] ?? ''));
    }

    private function genProgressTimeline(): string
    {
        $iconLis = '';
        $textLis = '';
        foreach ($this->options['steps'] as $i => $step) {
            $nodeActive = $i <= $this->options['selected'];
            $lineActive = $i < $this->options['selected'];
            $iconLis .= $this->getStepIcon($step, $i, $nodeActive, $lineActive);
            $textLis .= $this->getStepText($step, $nodeActive);
        }
        $ulIcons = $this->node('ul', [
            'class' => [
                'd-flex', 'justify-content-around',
            ],
        ], $iconLis);
        $ulText = $this->node('ul', [
            'class' => [
                'd-flex', 'justify-content-between',
            ],
        ], $textLis);
        $html = $this->node('div', [
            'class' => ['progress-timeline', 'mw-75', 'mx-auto']
        ], $ulIcons . $ulText);
        return $html;
    }
}