<?php

namespace App\View\Helper\BootstrapElements;

use App\View\Helper\BootstrapGeneric;

/**
 * Creates a Bootstrap card with the given options
 * 
 * # Options:
 * - headerText, bodyText, footerText: The text for the mentioned card component
 * - headerHTML, bodyHTML, footerHtml: The HTML for the mentioned card component
 * - class: A list of additional class to be added to the main container
 * - headerVariant, bodyVariant, footerVariant: The variant for the mentioned card component
 * - headerClass, bodyClass, footerClass: A list of additional class to be added to the main container
 * 
 * # Usage:
 * $this->Bootstrap->card([
 *    'headerText' => 'header',
 *    'bodyHTML' => '<i>body</i>',
 *    'footerText' => 'footer',
 *    'headerVariant' => 'warning',
 *    'footerVariant' => 'dark',
 * );
 */
class BootstrapCard extends BootstrapGeneric
{
    private $defaultOptions = [
        'headerText' => '',
        'bodyText' => '',
        'footerText' => '',
        'headerHTML' => null,
        'bodyHTML' => null,
        'footerHTML' => null,
        'class' => [],
        'headerVariant' => '',
        'bodyVariant' => '',
        'footerVariant' => '',
        'headerClass' => '',
        'bodyClass' => '',
        'footerClass' => '',
    ];

    public function __construct(array $options)
    {
        $this->allowedOptionValues = [
            'headerVariant' => array_merge(BootstrapGeneric::$variants, ['']),
            'bodyVariant' => array_merge(BootstrapGeneric::$variants, ['']),
            'footerVariant' => array_merge(BootstrapGeneric::$variants, ['']),
        ];
        $this->processOptions($options);
    }

    private function processOptions(array $options): void
    {
        $this->options = array_merge($this->defaultOptions, $options);
        $this->options['headerClass'] = $this->convertToArrayIfNeeded($this->options['headerClass']);
        $this->options['bodyClass'] = $this->convertToArrayIfNeeded($this->options['bodyClass']);
        $this->options['footerClass'] = $this->convertToArrayIfNeeded($this->options['footerClass']);
        $this->checkOptionValidity();
        $this->options['borderVariant'] = !empty($this->options['headerVariant']) ? "border-{$this->options['headerVariant']}" : '';
    }

    public function card(): string
    {
        return $this->genCard();
    }

    private function genCard(): string
    {
        $card = $this->node('div', [
            'class' => array_merge(
                [
                    'card',
                    $this->options['borderVariant'],
                ],
                $this->options['class']
            ),
        ], implode('', [$this->genHeader(), $this->genBody(), $this->genFooter()]));
        return $card;
    }

    private function genHeader(): string
    {
        if (empty($this->options['headerHTML']) && empty($this->options['headerText'])) {
            return '';
        }
        $content = $this->options['headerHTML'] ?? h($this->options['headerText']);
        $header = $this->node('div', [
            'class' => array_merge(
                [
                    'card-header',
                    self::getBGAndTextClassForVariant($this->options['headerVariant']),
                ],
                $this->options['headerClass']
            ),
        ], $content);
        return $header;
    }

    private function genBody(): string
    {
        if (empty($this->options['bodyHTML']) && empty($this->options['bodyText'])) {
            return '';
        }
        $content = $this->options['bodyHTML'] ?? h($this->options['bodyText']);
        $body = $this->node('div', [
            'class' => array_merge(
                [
                    'card-body',
                    self::getBGAndTextClassForVariant($this->options['bodyVariant']),
                ],
                $this->options['bodyClass']
            )
        ], $content);
        return $body;
    }

    private function genFooter(): string
    {
        if (empty($this->options['footerHTML']) && empty($this->options['footerText'])) {
            return '';
        }
        $content = $this->options['footerHTML'] ?? h($this->options['footerText']);
        $footer = $this->node('div', [
            'class' => array_merge([
                    'card-footer',
                    self::getBGAndTextClassForVariant($this->options['footerVariant']),
                ],
                $this->options['footerClass']
            )
        ], $content);
        return $footer;
    }
}