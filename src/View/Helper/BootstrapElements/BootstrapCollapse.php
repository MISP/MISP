<?php

namespace App\View\Helper\BootstrapElements;

use Cake\Utility\Security;

use App\View\Helper\BootstrapGeneric;
use App\View\Helper\BootstrapHelper;

/**
 * Creates a Bootstrap collapsible component
 * 
 * # Options:
 * - text: The text of the control element
 * - html: The HTML content of the control element
 * - open: Should the collapsible element be opened by default
 * - horizontal: Should the collapsible be revealed from the side
 * - class: List of additional classes to be added to the main container
 * - id: Optional ID to link the collapsible element with its control button
 * - button: Configuration object to make the control element into a button. Accepts BootstrapElements\BootstrapButton parameters
 * - card: Configuration object to adjust the content container based on configuration. Accepts BootstrapElements\BootstrapCard parameters
 * 
 * # Usage:
 * $this->Bootstrap->collapse([
 *     'button' => [
 *         'text' => 'Open sesame',
 *         'variant' => 'success',
 *     ],
 *     'card' => [
 *         'bodyClass' => 'p-2 rounded-3',
 *         'bodyVariant' => 'secondary',
 *     ]
 * ], '<i>content</i>');
 */

class BootstrapCollapse extends BootstrapGeneric
{
    private $defaultOptions = [
        'text' => '',
        'html' => null,
        'open' => false,
        'horizontal' => false,
        'class' => [],
        'button' => [],
        'card' => false,
        'attrs' => [],
    ];

    function __construct(array $options, string $content, BootstrapHelper $btHelper)
    {
        $this->allowedOptionValues = [];
        $this->processOptions($options);
        $this->content = $content;
        $this->btHelper = $btHelper;
    }

    private function processOptions(array $options): void
    {
        $this->options = array_merge($this->defaultOptions, $options);
        $this->options['class'] = $this->convertToArrayIfNeeded($this->options['class']);
        $this->options['class'][] = 'collapse';
        if (!empty($this->options['horizontal'])) {
            $this->options['class'][] = 'collapse-horizontal';
        }
        if ($this->options['open']) {
            $this->options['class'][] = 'show';
        }
        if ($this->options['card'] !== false && empty($this->options['card']['bodyClass'])) {
            $this->options['card']['bodyClass'] = ['p-0'];
        }
        if (empty($this->options['id'])) {
            $this->options['id'] = 'c-' . Security::randomString(8);
        }
        $this->checkOptionValidity();
    }

    public function collapse(): string
    {
        return $this->genCollapse();
    }

    private function genControl(): string
    {
        $attrsConfig = [
            'data-bs-toggle' => 'collapse',
            'role' => 'button',
            'aria-expanded' => 'false',
            'aria-controls' => $this->options['id'],
            'href' => '#' . $this->options['id'],
        ];
        $html = '';
        if (!empty($this->options['button'])) {
            $btnConfig = array_merge($this->options['button'], ['attrs' => $attrsConfig]);
            $html = $this->btHelper->button($btnConfig);
        } else {
            $nodeConfig = [
                'class' => ['text-decoration-none'],
            ];
            $nodeConfig = array_merge($nodeConfig, $attrsConfig);
            $html = $this->node('a', $nodeConfig, $this->options['html'] ?? h($this->options['text']));
        }
        return $html;
    }

    private function genContent(): string
    {
        if (!empty($this->options['card'])) {
            $cardConfig = $this->options['card'];
            $cardConfig['bodyHTML'] = $this->content;
            $content = $this->btHelper->card($cardConfig);
        } else {
            $content = $this->content;
        }
        $container = $this->node('div', [
            'class' => $this->options['class'],
            'id' => $this->options['id'],
        ], $content);
        return $container;
    }

    private function genCollapse(): string
    {
        return $this->genControl() . $this->genContent();
    }
}