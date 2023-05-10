<?php

namespace Tags\View\Helper;

use Cake\View\Helper;
use Cake\Utility\Hash;

class TagHelper extends Helper
{
    public $helpers = [
        'Bootstrap',
        'TextColour',
        'FontAwesome',
        'Form',
        'Url',
        'Tags.Tag',
    ];

    protected $defaultConfig = [
        'default_colour' => '#924da6',
        'picker' => false,
        'editable' => false,
    ];

    public function control(array $options = [])
    {
        $field = 'tag_list';
        $values = !empty($options['allTags']) ? array_map(function($tag) {
            return [
                'text' => h($tag['name']),
                'value' => h($tag['name']),
                'data-colour' => h($tag['colour']),
                'data-text-colour' => h($tag['text_colour']),
            ];
        }, $options['allTags']) : [];
        $classes = ['select2-input', 'flex-grow-1'];
        $url = '';
        if (!empty($this->getConfig('editable'))) {
            $url = $this->Url->build([
                'controller' => $this->getView()->getName(),
                'action' => 'tag',
                $this->getView()->get('entity')['id']
            ]);
            $classes[] = 'd-none';
        }
        $selectConfig = [
            'multiple' => true,
            'class' => $classes,
            'data-url' => $url,
        ];
        return $this->Form->select($field, $values, $selectConfig);
    }

    protected function picker(array $options = [])
    {
        $html =  $this->Tag->control($options);
        if (!empty($this->getConfig('editable'))) {
            $html .= $this->Bootstrap->button([
                'size' => 'sm',
                'icon' => 'plus',
                'variant' => 'secondary',
                'class' => ['badge'],
                'onclick' => 'createTagPicker(this)',
            ]);
        } else {
            $html .= '<script>$(document).ready(function() { initSelect2Pickers() })</script>';
        }
        return $html;
    }

    public function tags($tags = [], array $options = [])
    {
        $tags = is_null($tags) ? [] : $tags;
        $this->_config = array_merge($this->defaultConfig, $options);
        $html = '<div class="tag-container-wrapper">';
        $html .= '<div class="tag-container my-1 d-flex">';
        $html .= '<div class="tag-list d-inline-block">';
        foreach ($tags as $tag) {
            if (is_object($tag)) {
                $html .= $this->tag($tag);
            } else {
                $html .= $this->tag([
                    'name' => $tag
                ]);
            }
        }
        $html .= '</div>';
        
        if (!empty($this->getConfig('picker'))) {
            $html .= $this->picker($options);
        }
        $html .= '</div>';
        $html .= '</div>';
        return $html;
    }

    public function tag($tag, array $options = [])
    {
        if (empty($this->_config)) {
            $this->_config = array_merge($this->defaultConfig, $options);
        }
        $tag['colour'] = !empty($tag['colour']) ? $tag['colour'] : $this->getConfig('default_colour');
        $textColour = !empty($tag['text_colour']) ? $tag['text_colour'] : $this->TextColour->getTextColour(h($tag['colour']));;

        if (!empty($this->getConfig('editable'))) {
            $deleteButton = $this->Bootstrap->button([
                'size' => 'sm',
                'icon' => 'times',
                'class' => ['ms-1', 'border-0', "text-$textColour"],
                'variant' => 'text',
                'title' => __('Delete tag'),
                'onclick' => sprintf('deleteTag(\'%s\', \'%s\', this)',
                    $this->Url->build([
                        'controller' => $this->getView()->getName(),
                        'action' => 'untag',
                        $this->getView()->get('entity')['id']
                    ]),
                    h($tag['name'])
                ),
            ]);
        } else {
            $deleteButton = '';
        }

        $html = $this->Bootstrap->node('span', [
            'class' => [
                'tag',
                'badge',
                'mx-1',
                'align-middle',
            ],
            'title' => h($tag['name']),
            'style' => sprintf('color:%s; background-color:%s', $textColour, h($tag['colour'])),
        ], h($tag['name']) . $deleteButton);
        return $html;
    }
}
