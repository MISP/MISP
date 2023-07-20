<?php
include_once APP . 'Model/WorkflowModules/action/Module_tag_replacement_generic.php';

class Module_tag_replacement_pap extends Module_tag_replacement_generic
{
    public $version = '0.1';
    public $blocking = false;
    public $id = 'tag_replacement_pap';
    public $name = 'Tag Replacement - PAP';
    public $description = 'Attach a tag (or substitue) a tag by another for the PAP taxonomy';
    public $icon = 'tags';
    public $inputs = 1;
    public $outputs = 1;
    public $support_filters = true;
    public $expect_misp_core_format = true;
    public $params = [];

    public $searchRegex = '/(\w*pap\w*|permissible\W+actions\W+protocol)([:\s\-=]{1,2})"?(?P<predicate>white|clear|green|amber|red)"?/i';


    protected function isAMatch($matches): bool
    {
        $namespace = 'pap';
        $predicates = ['white', 'clear', 'green', 'amber', 'red'];
        if (empty($matches)) {
            return false;
        }
        return strtolower($matches[1]) == $namespace && in_array(strtolower($matches['predicate']), $predicates);
    }

    protected function formatSubstitution($matches)
    {
        return sprintf('PAP:%s', strtoupper($matches['predicate']));
    }

}
