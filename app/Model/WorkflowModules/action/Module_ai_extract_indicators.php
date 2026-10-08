<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

/**
 * Extract indicators from the matching event reports with the AI module
 * (A4, use-case infoextraction) and add them to the event as the
 * workflow's user, each tagged ai-computer-assisted (direct apply, no
 * review). One unpublish, through the module-result path import modules
 * use.
 *
 * Loop guard: a report an attribute comment of the event already cites
 * ("extracted by ai_connector from EventReport <uuid>") is left alone, so a
 * workflow on a save trigger holding this node does not pay an LLM call on
 * every save of the event it just changed; the module's own
 * de-duplication would only save the write. Nothing left to send: the node
 * succeeds without calling the module.
 */
class Module_ai_extract_indicators extends WorkflowBaseActionModule
{
    public $id = 'ai-extract-indicators';
    public $name = 'Extract indicators with AI';
    public $version = '0.1';
    public $description = 'Send the matching event reports to the AI module and add the indicators it reads out of them to the event, each tagged ai-computer-assisted. Reports an earlier extraction already covered are left alone.';
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
        $eventId = isset($rData['Event']['id']) ? (int)$rData['Event']['id'] : 0;
        $candidates = [];
        foreach ($reports as $report) {
            if (empty($report['uuid']) || !empty($report['deleted'])) {
                continue;
            }
            $candidates[] = strtolower($report['uuid']);
            if (!$eventId && !empty($report['event_id'])) {
                $eventId = (int)$report['event_id'];
            }
        }
        if (empty($candidates) || !$eventId) {
            return true;
        }
        if (!Configure::read('Plugin.AI_services_enable')) {
            $errors[] = __('The AI services are not enabled on this instance.');
            return false;
        }
        $Event = ClassRegistry::init('Event');
        $remaining = array_values(array_diff($candidates, $Event->aiExtractedReportUuids($eventId)));
        if (empty($remaining)) {
            return true;
        }
        try {
            $Event->aiExtractAndApply($roamingData->getUser(), $eventId, $remaining);
        } catch (Exception $e) {
            $errors[] = __('Event %s: %s', $eventId, $e->getMessage());
            return false;
        }
        return true;
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
            } elseif (isset($item['uuid']) && array_key_exists('content', $item)) {
                $reports[] = $item;
            }
        }
        return $reports;
    }
}
