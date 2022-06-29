<?php
App::uses('ProcessTool', 'Tools');

class GitTool
{
    /**
     * @param HttpSocketExtended $HttpSocket
     * @return array
     * @throws HttpSocketHttpException
     * @throws HttpSocketJsonException
     */
    public static function getLatestTags(HttpSocketExtended $HttpSocket)
    {
        $url = 'https://api.github.com/repos/MISP/MISP/tags?per_page=10';
        $response = $HttpSocket->get($url);
        if (!$response->isOk()) {
            throw new HttpSocketHttpException($response, $url);
        }
        return $response->json();
    }

    /**
     * @param HttpSocketExtended $HttpSocket
     * @return string
     * @throws HttpSocketHttpException
     * @throws HttpSocketJsonException
     */
    public static function getLatestCommit(HttpSocketExtended $HttpSocket)
    {
        $url = 'https://api.github.com/repos/MISP/MISP/commits?per_page=1';
        $response = $HttpSocket->get($url);
        if (!$response->isOk()) {
            throw new HttpSocketHttpException($response, $url);
        }
        $data = $response->json();
        if (!isset($data[0]['sha'])) {
            throw new Exception("Response do not contains requested data.");
        }
        return $data[0]['sha'];
    }

    /**
     * `git rev-parse HEAD`
     * @return string
     * @throws Exception
     */
    public static function currentCommit()
    {
        $head = rtrim(FileAccessTool::readFromFile(ROOT . '/.git/HEAD'));
        if (substr($head, 0, 5) === 'ref: ') {
            $path = substr($head, 5);
            return rtrim(FileAccessTool::readFromFile(ROOT . '/.git/' . $path));
        }  else if (strlen($head) === 40) {
            return $head;
        } else {
            throw new Exception("Invalid head $head");
        }
    }

    /**
     * `git symbolic-ref HEAD`
     * @return string
     * @throws Exception
     */
    public static function currentBranch()
    {
        $head = rtrim(FileAccessTool::readFromFile(ROOT . '/.git/HEAD'));
        if (substr($head, 0, 5) === 'ref: ') {
            $path = substr($head, 5);
            return str_replace('refs/heads/', '', $path);
        } else {
            throw new Exception("ref HEAD is not a symbolic ref");
        }
    }

    /**
     * @return array
     * @throws Exception
     */
    public static function submoduleStatus()
    {
        $lines = ProcessTool::execute(['git', 'submodule', 'status', '--cached'], ROOT);
        $output = [];
        foreach (explode("\n", $lines) as $submodule) {
            if ($submodule === '' || $submodule[0] === '-') {
                continue;
            }
            $parts = explode(' ', $submodule);
            $output[] = [
                'name' => $parts[2],
                'commit' => $parts[1],
            ];
        }
        return $output;
    }

    /**
     * @param string $submodule Path to Git repo
     * @return string|null
     */
    public static function submoduleCurrentCommit($submodule)
    {
        try {
            $commit = ProcessTool::execute(['git', 'rev-parse', 'HEAD'], $submodule);
        } catch (ProcessException $e) {
            return null;
        }
        return rtrim($commit);
    }

    /**
     * @param string $commit
     * @param string|null $submodule Path to Git repo
     * @return int|null
     */
    public static function commitTimestamp($commit, $submodule = null)
    {
        try {
            $timestamp = ProcessTool::execute(['git', 'show', '-s', '--pretty=format:%ct', $commit], $submodule);
        } catch (ProcessException $e) {
            return null;
        }
        return (int)rtrim($timestamp);
    }
}
