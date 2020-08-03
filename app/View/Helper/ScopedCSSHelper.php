<?php
App::uses('AppHelper', 'View/Helper');

    // prepend user names on the header with some text based on the given rules
    class ScopedCSSHelper extends AppHelper {

        private function endsWith($haystack, $needle)
        {
            $length = strlen($needle);
            if ($length == 0) {
                return true;
            }
            return (substr($haystack, -$length) === $needle);
        }

        private function preppendScopedId($css, $seed)
        {
            $prependSelector = sprintf('[data-scoped="%s"]', $seed);
            $cssLines = explode(PHP_EOL, $css);
            foreach ($cssLines as $i => $line) {
                if (strlen($line) > 0) {
                    if ($this->endsWith($line, "{") || $this->endsWith($line, ",")) {
                        $cssLines[$i] = sprintf("%s %s", $prependSelector, $line);
                    }
                }
            }
            $cssScopedLines = implode(PHP_EOL, $cssLines);
            return sprintf("<style>%s%s%s</style>", PHP_EOL, $cssScopedLines, PHP_EOL);
        }


         /**
         * Replace a declared CSS scoped style and prepend a random CSS data filter to any CSS selector discovered.
         * Usage: Add the following style tag `<style widget-scoped>` to use the scoped feature. Nearly every selector path will have their rule modified to adhere to the scope
         * Restrictions:
         *      - Applying class to the root document (i.e. `body`) will not work
         *      - Selector rules must end with either `{` or `,`, their content MUST be put in a new line:
         *          [bad]
         *              element { ... }
         *          [good]
         *              element {
         *                  ...
         *              }
         *      - Selectors with the `and` (`,`) rule MUST be split in multiple lines:
         *          [bad]
         *              element,element {
         *                  ...
         *              }
         *          [good]
         *              element,
         *              element {
         *                  ...
         *              }
         * @param string $param1 HTML potentially containing scoped CSS
         * @return array Return an array composed of 3 keys (html, css and seed)
         *      - bundle:       Include both scoped HTML and scoped CSS or the original html if the scoped feature is not requested
         *      - html:         Untouched HTML including nested in a scoped DIV or original html if the scoped feature is not requested
         *      - css:          CSS with an additional filter rule prepended to every selectors or the empty string if the scoped feature is not requested
         *      - seed:         The random generated number
         *      - originalHtml: Untouched HTML
         */
        public function createScopedCSS($html)
        {
            $css = "";
            $seed = "";
            $originalHtml = $html;
            $bundle = $originalHtml;
            $scopedHtml = $html;
            $scopedCss = "";
            $htmlStyleTag = "<style widget-scoped>";
            $styleClosingTag = "</style>";
            $styleTagIndex = strpos($html, $htmlStyleTag);
            $closingStyleTagIndex = strpos($html, $styleClosingTag, $styleTagIndex) + strlen($styleClosingTag);
            if ($styleTagIndex !== false && $closingStyleTagIndex !== false && $closingStyleTagIndex > $styleTagIndex) { // enforced scoped css
                $seed = rand();
                $css = substr($html, $styleTagIndex, $closingStyleTagIndex);
                $html = str_replace($css, "", $html); // remove CSS part
                $css = str_replace($htmlStyleTag, "", $css); // remove the style node
                $css = str_replace($styleClosingTag, "", $css); // remove closing style node
                $scopedCss = $this->preppendScopedId($css, $seed);
                $scopedHtml = sprintf("<div %s>%s</div>", sprintf("data-scoped=\"%s\" ", $seed), $html);
                $bundle = sprintf("%s %s", $scopedHtml, $scopedCss);
            }
            return array(
                "bundle" => $bundle,
                "html" => $scopedHtml,
                "css" => $scopedCss,
                "seed" => $seed,
                "originalHtml" => $originalHtml,
            );
        }

    }
