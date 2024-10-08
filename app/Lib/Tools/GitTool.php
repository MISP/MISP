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
        return self::gitHubRequest($HttpSocket, $url);
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
        $data = self::gitHubRequest($HttpSocket, $url);
        if (!isset($data[0]['sha'])) {
            throw new Exception("Response do not contains requested data.");
        }
        return $data[0]['sha'];
    }

    /**
     * @param HttpSocketExtended $HttpSocket
     * @param string $url
     * @return array
     * @throws HttpSocketHttpException
     * @throws HttpSocketJsonException
     */
    private static function gitHubRequest(HttpSocketExtended $HttpSocket, $url)
    {
        $response = $HttpSocket->get($url, [], ['header' => ['User-Agent' => 'MISP']]);
        if (!$response->isOk()) {
            throw new HttpSocketHttpException($response, $url);
        }
        return $response->json();
    }

    /**
     * Returns current SHA1 hash of current commit
     * `git rev-parse HEAD`
     * @param string $repoPath
     * @return string
     * @throws Exception
     */
    public static function currentCommit($repoPath)
    {
        if (is_file($repoPath . '/.git')) {
            $fileContent = FileAccessTool::readFromFile($repoPath . '/.git');
            if (str_starts_with($fileContent, 'gitdir: ')) {
                $gitDir = $repoPath . '/' . trim(substr($fileContent, 8)) . '/';
            } else {
                throw new Exception("$repoPath/.git is file, but contains non expected content $fileContent");
            }
        } else {
            $gitDir = $repoPath . '/.git/';
        }

        $head = rtrim(FileAccessTool::readFromFile($gitDir . 'HEAD'));
        if (str_starts_with($head, 'ref: ')) {
            $path = substr($head, 5);
            return rtrim(FileAccessTool::readFromFile($gitDir . $path));
        }  else if (strlen($head) === 40) {
            return $head;
        } else {
            throw new Exception("Invalid head '$head' in $gitDir/HEAD");
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
        if (str_starts_with($head, 'ref: ')) {
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
     * @param string $commit
     * @param string|null $submodule Path to Git repo
     * @return int|null
     * @throws Exception
     */
    public static function commitTimestamp($commit, $submodule = null)
    {
        try {
            $timestamp = ProcessTool::execute(['git', 'show', '-s', '--pretty=format:%ct', $commit], $submodule);
        } catch (ProcessException $e) {
            CakeLog::notice("Could not get Git commit timestamp for $submodule: {$e->getMessage()}");
            return null;
        }
        return (int)rtrim($timestamp);
    }
}
