<?php

namespace App\View\Helper\BootstrapElements;

use App\View\Helper\BootstrapGeneric;
use App\View\Helper\BootstrapHelper;

/**
 * Creates an collapsible accordion component
 * 
 * # Options:
 * - stayOpen: Should collapsible components stay open when another one is opened
 * - class: Additional classes to add to the main accordion container
 * - content: Definition of the collapsible components. Must have at least the $body key set. See the "# Content" section for the options
 *
 * # Content:
 * - class: Additional class to add to the body container
 * - open: Should that collapsible element be opened by default
 * - variant: The background variant to be applied to the body element
 * - header: The definition of the interactive header. Accepts the following options:
 *      - variant: The bootstrap variant to apply on the header element
 *      - text: The text content of the header
 *      - html: The HTML content of the header
 * 
 * # Usage:
 * $this->Bootstrap->accordion(
 *     [
 *         'stayOpen' => true,
 *     ],
 *     [
 *         [
 *             'open' => true,
 *             'header' => [
 *                 'variant' => 'danger',
 *                 'text' => 'nav 1',
 *             ],
 *             'body' => '<b>body</b>',
 *         ],
 *         [
 *             'class' => ['opacity-50'],
 *             'variant' => 'success',
 *             'header' => [
 *                 'html' => '<i>nav 1</i>',
 *             ],
 *             'body' => '<b>body</b>',
 *         ],
 *     ]
 * );
 */
class BootstrapAccordion extends BootstrapGeneric
{
    private $defaultOptions = [
        'stayOpen' => false,
        'class' => [],
    ];

    function __construct(array $options, array $content, BootstrapHelper $btHelper)
    {
        $this->allowedOptionValues = [];
        $this->content = $content;
        $this->btHelper = $btHelper;
        $this->processOptions($options);
    }

    private function processOptions(array $options): void
    {
        $this->options = array_merge($this->defaultOptions, $options);
        $this->checkOptionValidity();
        $this->options['class'] = $this->convertToArrayIfNeeded($this->options['class']);
        $this->seed = 'acc-' . mt_rand();
        $this->contentSeeds = [];
        foreach ($this->content as $accordionItem) {
            $this->contentSeeds[] = mt_rand();
        }

        foreach ($this->content as $i => $item) {
            $this->content[$i]['class'] = $this->convertToArrayIfNeeded($item['class'] ?? []);
            $this->content[$i]['header']['class'] = $this->convertToArrayIfNeeded($item['header']['class'] ?? []);
        }
    }

    public function accordion(): string
    {
        return $this->genAccordion();
    }

    private function genHeader(array $accordionItem, int $i): string
    {
        $html = $this->nodeOpen('h2', [
            'class' => ['accordion-header'],
            'id' => 'head-' . $this->contentSeeds[$i]
        ]);
        $content = $accordionItem['header']['html'] ?? h($accordionItem['header']['text']);
        $buttonOptions = [
            'class' => array_merge(
                [
                    'accordion-button',
                    empty($accordionItem['open']) ? 'collapsed' : '',
                    self::getBGAndTextClassForVariant($accordionItem['header']['variant'] ?? ''),
                ],
                $accordionItem['header']['class'],
            ),
            'type' => 'button',
            'data-bs-toggle' => 'collapse',
            'data-bs-target' => '#body-' . $this->contentSeeds[$i],
            'aria-expanded' => 'false',
            'aria-controls' => 'body-' . $this->contentSeeds[$i],
        ];
        $html .= $this->node('button', $buttonOptions, $content);
        $html .= $this->nodeClose(('h2'));
        return $html;
    }

    private function genBody(array $accordionItem, int $i): string
    {
        $content = $this->node('div', [
            'class' => ['accordion-body']
        ], $accordionItem['body']);
        $divOptions = [
            'class' => array_merge(
                [
                    'accordion-collapse collapse',
                    empty($accordionItem['open']) ? '' : 'show',
                    self::getBGAndTextClassForVariant($accordionItem['variant'] ?? ''),
                ],
                $accordionItem['class'],
            ),
            'id' => 'body-' . $this->contentSeeds[$i],
            'aria-labelledby' => 'head-' . $this->contentSeeds[$i],
        ];
        if (empty($this->options['stayOpen'])) {
            $divOptions['data-bs-parent'] = '#' . $this->seed;
        }
        $html = $this->node('div', $divOptions, $content);
        return $html;
    }

    private function genAccordion(): string
    {
        $html = $this->nodeOpen('div', [
            'class' => array_merge(['accordion'], $this->options['class']),
            'id' => $this->seed
        ]);
        foreach ($this->content as $i => $accordionItem) {
            $html .= $this->nodeOpen('div', [
                'class' => array_merge(['accordion-item'])
            ]);
            $html .= $this->genHeader($accordionItem, $i);
            $html .= $this->genBody($accordionItem, $i);
            $html .= $this->nodeClose('div');
        }
        $html .= $this->nodeClose('div');
        return $html;
    }
}