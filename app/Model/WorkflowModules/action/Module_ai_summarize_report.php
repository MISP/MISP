<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

/**
 * Summarise the matching event reports with the AI module: the module puts
 * its summary on top of each report (EventReport::aiSummarize()).
 *
 * Successor of the CTIInfoExtractor node. The id is kept so that stored
 * workflows keep working; the label changed and the old yes/no params are
 * gone (ignored when a stored node still carries them). A report that
 * already carries an AI summary is left alone: that keeps the node
 * idempotent, and keeps a workflow on the event-report-after-save trigger
 * from feeding the edit it makes back to itself. A summary is replaced from
 * the report page.
 */
class Module_ai_summarize_report extends WorkflowBaseActionModule
{
    public $id = 'send-report-to-cti-info-extractor';
    public $name = 'Summarise report with AI';
    public $version = '0.2';
    public $description = 'Send the matching event reports to the AI module, which puts its summary on top of each report. Reports that already carry an AI summary are left alone.';
    public $icon = 'robot';
    public $inputs = 1;
    public $outputs = 1;
    public $support_filters = true;
    public $expect_misp_core_format = true;
    public $params = [];

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors = []): bool
    {
        parent::exec($node, $roamingData, $errors);
        $rData = $roamingData->getData();
        if ($this->filtersEnabled($node)) {
            $filters = $this->getFilters($node);
            $extracted = $this->extractData($rData, $filters['selector']);
            if ($extracted === false) {
                return false;
            }
            $matchingItems = $this->getItemsMatchingCondition($extracted, $filters['value'], $filters['operator'], $filters['path']);
        } else {
            $matchingItems = $rData;
        }
        $reports = $this->collectReports($matchingItems);
        if (empty($reports)) {
            return true;
        }
        if (!Configure::read('Plugin.AI_services_enable')) {
            $errors[] = __('The AI services are not enabled on this instance.');
            return false;
        }
        $EventReport = ClassRegistry::init('EventReport');
        $user = $roamingData->getUser();
        $success = true;
        foreach ($reports as $report) {
            if (empty($report['id']) || !empty($report['deleted'])) {
                continue;
            }
            $content = isset($report['content']) ? (string)$report['content'] : '';
            if (EventReport::stripAiSummary($content) !== $content) {
                continue;
            }
            try {
                $EventReport->aiSummarize($user, (int)$report['id']);
            } catch (Exception $e) {
                $errors[] = __('Report %s: %s', $report['id'], $e->getMessage());
                $success = false;
            }
        }
        return $success;
    }

    /**
     * The event reports in the (filtered) data, whichever selector shaped
     * it: the whole event (no filter), a list holding the event (selector
     * `Event`) or a list of reports (selector `Event.EventReport.{n}`).
     *
     * @param mixed $items
     * @return array
     */
    private function collectReports($items): array
    {
        if (!is_array($items)) {
            return [];
        }
        if (isset($items['Event']['EventReport']) && is_array($items['Event']['EventReport'])) {
            return $items['Event']['EventReport'];
        }
        $reports = [];
        foreach ($items as $item) {
            if (!is_array($item)) {
                continue;
            }
            if (isset($item['EventReport']) && is_array($item['EventReport'])) {
                $reports = array_merge($reports, $item['EventReport']);
            } elseif (isset($item['id']) && array_key_exists('content', $item)) {
                $reports[] = $item;
            }
        }
        return $reports;
    }
}
