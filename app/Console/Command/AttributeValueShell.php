<?php
App::uses('AttributeValueBackfillTool', 'Tools');
App::uses('CorrelationRemapTool', 'Tools');
App::uses('ValueFacetTool', 'Tools');

/**
 * @property AttributeValue $AttributeValue
 */
class AttributeValueShell extends AppShell
{
    public $uses = ['AttributeValue'];

    const TABLES = ['attributes', 'shadow_attributes'];

    // Seconds between progress lines
    const PROGRESS_EVERY = 10;

    public function getOptionParser()
    {
        $parser = parent::getOptionParser();
        $options = [
            'chunk-size' => [
                'help' => __('Rows per chunk.'),
                'default' => AttributeValueBackfillTool::CHUNK,
            ],
        ];
        $parser->addSubcommand('backfill', [
            'help' => __('Set the value ids of attributes and proposals from their text, adding the values the dictionary lacks. A stopped run resumes where it left off.'),
            'parser' => ['options' => $options],
        ]);
        $parser->addSubcommand('remapCorrelations', [
            'help' => __('Point the correlations the value id migration found, and the over-correlating values, at the value dictionary instead of their text. Run it after the backfill. A stopped run resumes where it left off.'),
            'parser' => ['options' => [
                'chunk-size' => [
                    'help' => __('Rows per chunk.'),
                    'default' => CorrelationRemapTool::CHUNK,
                ],
            ]],
        ]);
        $parser->addSubcommand('rebuildFacets', [
            'help' => __('Bring the IP facet (value_ip_ranges) in line with the value dictionary: add the rows of values that parse as an IP address or CIDR, replace rows that differ, remove the rest. Rows that are already right are left alone, so a stopped run resumes by starting it again.'),
            'parser' => ['options' => [
                'chunk-size' => [
                    'help' => __('Dictionary ids per window.'),
                    'default' => ValueFacetTool::CHUNK,
                ],
            ]],
        ]);
        $parser->addSubcommand('verify', [
            'help' => __('Check that every attribute and proposal has value ids that give back its text byte for byte, and that every dictionary row holds the hash of its value. Changes nothing.'),
            'parser' => ['options' => $options],
        ]);
        return $parser;
    }

    public function backfill()
    {
        $tool = new AttributeValueBackfillTool($this->AttributeValue);
        foreach (self::TABLES as $table) {
            if (!$tool->hasText($table)) {
                $this->out(sprintf('%s: no text columns left, nothing to backfill.', $table));
                continue;
            }
            $start = microtime(true);
            $totals = $tool->backfill($table, $this->param('chunk-size'), $this->progress($start, function (array $totals) use ($table) {
                return sprintf('%s: %d rows given ids, %d values added, up to id %d', $table, $totals['rows'], $totals['values'], $totals['last_id']);
            }));
            $this->out(sprintf(
                '%s: done, %d rows given ids, %d values added, %.1f s.',
                $table,
                $totals['rows'],
                $totals['values'],
                microtime(true) - $start
            ));
        }
    }

    public function remapCorrelations()
    {
        $this->out(sprintf(
            'over_correlating_values: %d rows given value ids.',
            ClassRegistry::init('OverCorrelatingValue')->remapValueIds()
        ));
        $tool = new CorrelationRemapTool($this->AttributeValue);
        foreach (CorrelationRemapTool::TABLES as $table) {
            $start = microtime(true);
            $totals = $tool->remap($table, $this->param('chunk-size'), $this->progress($start, function (array $totals) use ($table) {
                return sprintf('%s: %d rows remapped, up to id %d', $table, $totals['rows'], $totals['last_id']);
            }));
            $this->out(sprintf(
                '%s: done, %d rows remapped (%d one by one), %d repeated pairs dropped, %.1f s.',
                $table,
                $totals['rows'],
                $totals['by_row'],
                $totals['dropped'],
                microtime(true) - $start
            ));
        }
        $tool->finish();
    }

    public function rebuildFacets()
    {
        $start = microtime(true);
        $totals = $this->AttributeValue->facets()->rebuild($this->param('chunk-size'), $this->progress($start, function (array $totals) {
            return sprintf('value_ip_ranges: %d values read, %d added, %d removed, up to id %d', $totals['values'], $totals['added'], $totals['removed'], $totals['last_id']);
        }));
        $this->out(sprintf(
            'value_ip_ranges: done, %d values read, %d parse as an address or CIDR, %d rows added, %d removed, %.1f s.',
            $totals['values'],
            $totals['facets'],
            $totals['added'],
            $totals['removed'],
            microtime(true) - $start
        ));
    }

    public function verify()
    {
        $tool = new AttributeValueBackfillTool($this->AttributeValue);
        $chunkSize = $this->param('chunk-size');
        $failed = false;
        foreach (self::TABLES as $table) {
            if (!$tool->hasText($table)) {
                $this->out(sprintf('%s: no text columns left to check the ids against.', $table));
                continue;
            }
            $start = microtime(true);
            $counts = $tool->verify($table, $chunkSize, $this->progress($start, function (array $counts) use ($table) {
                return sprintf('%s: %d rows checked', $table, $counts['total']);
            }));
            $this->out(sprintf(
                '%s: %d rows, %d without ids, %d mismatched%s, %.1f s.',
                $table,
                $counts['total'],
                $counts['pending'],
                $counts['mismatched'],
                $counts['first_mismatch'] === null ? '' : sprintf(' (first id %d)', $counts['first_mismatch']),
                microtime(true) - $start
            ));
            $failed = $failed || $counts['pending'] > 0 || $counts['mismatched'] > 0;
        }
        $start = microtime(true);
        $counts = $tool->verifyDictionary($chunkSize, $this->progress($start, function (array $counts) {
            return sprintf('dictionary: %d rows checked', $counts['total']);
        }));
        $this->out(sprintf(
            'dictionary: %d rows, %d not matching their hash%s, %.1f s.',
            $counts['total'],
            $counts['mismatched'],
            $counts['first_mismatch'] === null ? '' : sprintf(' (first id %d)', $counts['first_mismatch']),
            microtime(true) - $start
        ));
        if ($failed || $counts['mismatched'] > 0) {
            $this->error(__('Verification failed.'));
        }
        $this->out(__('All rows verified.'));
    }

    /**
     * @param float $start
     * @param callable $line Builds the progress line from the counts.
     * @return callable
     */
    private function progress($start, callable $line)
    {
        $printed = $start;
        return function (array $counts) use ($start, $line, &$printed) {
            $now = microtime(true);
            if ($now - $printed >= self::PROGRESS_EVERY) {
                $printed = $now;
                $this->out(sprintf('%s, %d s', $line($counts), $now - $start));
            }
        };
    }
}
