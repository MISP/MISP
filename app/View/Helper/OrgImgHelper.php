<?php
App::uses('AppHelper', 'View/Helper');

// Helper to retrieve org images with the given parameters
    class OrgImgHelper extends AppHelper {
        const IMG_PATH = APP . WEBROOT_DIR . DS . 'img' . DS . 'orgs' . DS;

        public function getOrgImg($options, $returnData = false, $raw = false) {
            $imgOptions = array();
            $possibleFields = array('id', 'name');
            $size = !empty($options['size']) ? $options['size'] : 48;
            foreach ($possibleFields as $field) {
                if (isset($options[$field]) && file_exists(self::IMG_PATH . $options[$field] . '.png')) {
                    $imgOptions[$field] = $options[$field] . '.png';
                    break;
                }
            }
            if (!empty($imgOptions)) {
                foreach ($imgOptions as $field => $imgOption) {
                    $result = sprintf(
                        '<img src="%s/img/orgs/%s" title="%s" width="%s" height="%s">',
                        $baseurl,
                        $imgOption,
                        isset($options['name']) ? h($options['name']) : h($options['id']),
                        (int)$size,
                        (int)$size
                    );

                    if (!$raw) {
                        $result = sprintf(
                            '<a href="%s/organisations/view/%s">%s</a>',
                            $baseurl,
                            (empty($options['id']) ? h($options['name']) : h($options['id'])),
                            $result
                        );
                    }
                    break;
                }
            } else {
                if ($raw) {
                    $result = sprintf(
                        '<span class="welcome">%s</span>',
                        h($options['name'])
                    );
                } else {
                    $result = sprintf(
                        '<a href="%s/organisations/view/%s"><span class="welcome">%s</span></a>',
                        $baseurl,
                        (empty($options['id']) ? h($options['name']) : h($options['id'])),
                        h($options['name'])
                    );
                }

            }
            if ($returnData) {
                return $result;
            } else {
                echo $result;
            }
        }
    }
