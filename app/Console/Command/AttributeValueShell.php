<?php
App::uses('AttributeValueBackfillTool', 'Tools');

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

    public function verify()
    {
        $tool = new AttributeValueBackfillTool($this->AttributeValue);
        $chunkSize = $this->param('chunk-size');
        $failed = false;
        foreach (self::TABLES as $table) {
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
