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
            $cssLines = explode("\n", $css);
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

        public function createScopedCSS($html)
        {
            $css = "";
            $seed = "";
            $htmlStyleTag = "<style widget-scoped>";
            $styleClosingTag = "</style>";
            $styleTagIndex = strpos($html, $htmlStyleTag);
            $closingStyleTagIndex = strpos($html, $styleClosingTag) + strlen($styleClosingTag);
            if ($styleTagIndex !== false && $closingStyleTagIndex !== false && $closingStyleTagIndex > $styleTagIndex) { // enforced scoped css
                $seed = rand();
                $css = substr($html, $styleTagIndex, $closingStyleTagIndex);
                $html = str_replace($css, "", $html);           // remove CSS part
                $css = str_replace($htmlStyleTag, "", $css);    // remove the style node
                $css = str_replace($styleClosingTag, "", $css); // remove closing style node
                $css = $this->preppendScopedId($css, $seed);
            }
            return array(
                "seed" => $seed,
                "html" => $html,
                "css" => $css
            );
        }

    }
