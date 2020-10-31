<?php
App::uses('AppHelper', 'View/Helper');

// Helper to retrieve org images with the given parameters
class OrgImgHelper extends AppHelper
{
    const IMG_PATH = APP . WEBROOT_DIR . DS . 'img' . DS . 'orgs' . DS;

    public function getNameWithImg(array $organisation)
    {
        if (!isset($organisation['Organisation'])) {
            return '';
        }

        $orgImgName = null;
        foreach (['id', 'name'] as $field) {
            if (isset($organisation['Organisation'][$field]) && file_exists(self::IMG_PATH . $organisation['Organisation'][$field] . '.png')) {
                $orgImgName = $organisation['Organisation'][$field] . '.png';
                break;
            }
        }
        $baseurl = $this->_View->viewVars['baseurl'];
        $link = $baseurl . '/organisations/view/' . (empty($organisation['Organisation']['id']) ? h($organisation['Organisation']['name']) : h($organisation['Organisation']['id']));
        if ($orgImgName) {
            $orgImgUrl = $baseurl . '/img/orgs/' . $orgImgName;
            return sprintf('<a href="%s" style="background-image: url(\'%s\')" class="orgImg">%s</a>', $link, $orgImgUrl, h($organisation['Organisation']['name']));
        } else {
            return sprintf('<a href="%s">%s</a>', $link, h($organisation['Organisation']['name']));
        }
    }

    public function getOrgImg($options, $returnData = false, $raw = false)
    {
        $orgImgName = null;
        foreach (['id', 'name'] as $field) {
            if (isset($options[$field]) && file_exists(self::IMG_PATH . $options[$field] . '.png')) {
                $orgImgName = $options[$field] . '.png';
                break;
            }
        }
        $baseurl = $this->_View->viewVars['baseurl'];
        if ($orgImgName) {
            $size = !empty($options['size']) ? $options['size'] : 48;
            $result = sprintf(
                '<img src="%s/img/orgs/%s" title="%s" width="%s" height="%s">',
                $baseurl,
                $orgImgName,
                isset($options['name']) ? h($options['name']) : h($options['id']),
                (int)$size,
                (int)$size
            );

            if (!$raw) {
                $result = sprintf(
                    '<a href="%s/organisations/view/%s">%s</a>',
                    $baseurl,
                    empty($options['id']) ? h($options['name']) : h($options['id']),
                    $result
                );
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
                    empty($options['id']) ? h($options['name']) : h($options['id']),
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
