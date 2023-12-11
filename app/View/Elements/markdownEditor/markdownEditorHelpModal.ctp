<?php
/**
 * Accept `additionalMarkdownHelpModalElements` to add new tags. Format
 * additionalMarkdownHelpModalElements = {
 *     'tab_name' => 'The name of the tab',
 *     'tab_content' => 'The content of the tab',
 * }
 * 
 */
    $additionalTabsHTML = '';
    $additionalTabContentHTML = '';
    if (!empty($additionalMarkdownHelpModalElements)) {
        foreach ($additionalMarkdownHelpModalElements as $i => $tab) {
            $additionalMarkdownHelpModalElements[$i]['tab_id'] = 'tab-' . preg_replace('/[^a-zA-Z0-9]/', '_', $tab['tab_name']);
            $additionalTabsHTML .= sprintf('<li><a href="#%s">%s</a></li>', $additionalMarkdownHelpModalElements[$i]['tab_id'], $additionalMarkdownHelpModalElements[$i]['tab_name']);

            $additionalTabContentHTML .= sprintf('<div class="tab-pane active" id="%s">', $additionalMarkdownHelpModalElements[$i]['tab_id']);
            $additionalTabContentHTML .= $tab['tab_content'];
            $additionalTabContentHTML .= '</div>';

        }
    }
    $formatDifferences = [
        __('No html support, typographer & autolinker'),
        __('An additional syntax to reference MISP Elements'),
    ];
    $shortcutsTableHeader = [__('Command'), __('Action')];
    $shortcuts = [
        ['<kbd>' . implode('</kbd><kbd>', ['ctrl', ' + ', 'space']) . '</kbd>', __('Triggers autocomplete if applicable')],
        ['<kbd>' . implode('</kbd><kbd>', ['ctrl', ' + ', 'b']) . '</kbd>', __('Makes text bold')],
        ['<kbd>' . implode('</kbd><kbd>', ['ctrl', ' + ', 'i']) . '</kbd>', __('Makes text italic')],
        ['<kbd>' . implode('</kbd><kbd>', ['ctrl', ' + ', 'm']) . '</kbd>', __('Insert a MISP Element')],
        ['<kbd>' . implode('</kbd><kbd>', ['ctrl', ' + ', 'h']) . '</kbd>', __('Makes text as header')],
    ];

    $helpHTML = '';
    $helpHTML .= '<ul class="nav nav-tabs" id="tab-markdown-help">';
    $helpHTML .= $additionalTabsHTML;
    $helpHTML .=    sprintf('<li class=""><a href="#tab-editor">%s</a></li>', __('Editor shortcuts'));
    $helpHTML .=    sprintf('<li class=""><a href="#tab-plugin">%s</a></li>', __('Markdown plugin'));
    $helpHTML .= '</ul class="nav nav-tabs">';

    $helpHTML .= '<div class="tab-content">';
    $helpHTML .= $additionalTabContentHTML;

    $helpHTML .= '<div class="tab-pane" id="tab-editor">';
    $helpBodyHTML = '';
    foreach ($shortcuts as $sc) {
        $helpBodyHTML .= sprintf('<tr><td><kbd>%s</kbd></td><td>%s</td></tr>', $sc[0], $sc[1]);
    }
    $helpHTML .= sprintf('<h2>%s</h2>', __('Editor shortcuts'));
    $helpHTML .= sprintf('<table class="table table-bordered table-condensed"><thead><tr>%s</tr></thead><tbody>%s</tbody></table>',
        '<th>' . implode('</th><th>', $shortcutsTableHeader) . '</th>',
        $helpBodyHTML
    );
    $helpHTML .= '</div>';

    $helpHTML .= '<div class="tab-pane" id="tab-plugin">';
    $helpHTML .= sprintf('<h2>%s</h2>', __('Markdown plugins'));
    $helpHTML .= sprintf('<h3>%s</h3>', __('Highlighted language'));
    $helpHTML .= sprintf('<p>%s</p>', __('Languages rendered in code block can be highlighted using the %s plugin. The list of supported languages can be found %s.',
        sprintf('<a href="%s">%s</a>', 'https://highlightjs.org/', 'highlight.js'),
        sprintf('<a href="%s">%s</a>', 'https://github.com/highlightjs/highlight.js/blob/master/SUPPORTED_LANGUAGES.md', 'here')
    ));

    $helpHTML .= '</div>';

    $helpHTML .= '</div>';

    $data = array(
        'title' => __('Markdown viewer help'),
        'content' => array(
            array(
                'html' => $helpHTML
            ),
        )
    );
    echo $this->element('genericElements/infoModal', array('data' => $data, 'type' => 'lg', 'class' => 'markdown-modal-helper'));
?>

<script>
    $(document).ready(function() {
        $('#tab-markdown-help a').click(function (e) {
            e.preventDefault();
            $(this).tab('show');
        })
        $('#tab-markdown-help > li:first').addClass('active')
    })
</script>

<style>
/* borrowing from BS4 */
kbd {
    padding: .2rem .4rem;
    font-size: 87.5%;
    color: #fff;
    background-color: #212529;
    border-radius: .2rem;
}
kbd kbd {
    padding: 0;
    font-size: 100%;
    font-weight: 700;
}
</style>