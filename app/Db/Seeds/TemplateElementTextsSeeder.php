<?php

declare(strict_types=1);

use Phinx\Seed\AbstractSeed;

class TemplateElementTextsSeeder extends AbstractSeed
{
    public function run(): void
    {
        $data =  [
            ['id' => 1, 'name' => 'Required fields', 'template_element_id' => 3, 'text' => 'The fields below are mandatory.'],
            ['id' => 2, 'name' => 'Optional information', 'template_element_id' => 5, 'text' => 'All of the fields below are optional, please fill out anything that\'s applicable.'],
            ['id' => 4, 'name' => 'Required Fields', 'template_element_id' => 11, 'text' => 'The following fields are mandatory'],
            ['id' => 5, 'name' => 'Optional information about the payload delivery', 'template_element_id' => 13, 'text' => 'All of the fields below are optional, please fill out anything that\'s applicable. This section describes the payload delivery, including the e-mail itself, the attached file, the vulnerability it is exploiting and any malicious urls in the e-mail.'],
            ['id' => 6, 'name' => 'Optional information obtained from analysing the malicious file', 'template_element_id' => 16, 'text' => 'Information about the analysis of the malware (if applicable). This can include C2 information, artifacts dropped during the analysis, persistance mechanism, etc.'],
            ['id' => 7, 'name' => 'Malware Sample', 'template_element_id' => 29, 'text' => 'If you can, please upload the sample that the report revolves around.'],
            ['id' => 8, 'name' => 'Dropped Artifacts', 'template_element_id' => 31, 'text' => 'Describe any dropped artifacts that you have encountered during your analysis'],
            ['id' => 9, 'name' => 'C2 Information', 'template_element_id' => 32, 'text' => 'The following field deals with Command and Control information obtained during the analysis. All fields are optional.'],
            ['id' => 10, 'name' => 'Other Network Activity', 'template_element_id' => 33, 'text' => 'If any other Network activity (such as an internet connection test) was detected during the analysis, please specify it using the following fields'],
            ['id' => 11, 'name' => 'Persistence mechanism', 'template_element_id' => 41, 'text' => 'The following fields allow you to describe the persistence mechanism used by the malware'],
            ['id' => 12, 'name' => 'Indicators', 'template_element_id' => 45, 'text' => 'Just paste your list of indicators based on type into the appropriate field. All of the fields are optional, so inputting a list of IP addresses into the Network indicator field for example is sufficient to complete this template.'],
        ];

        $templateElementTexts = $this->table('template_element_texts');
        $templateElementTexts->insert($data)
            ->saveData();
    }
}
