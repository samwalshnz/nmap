<?php

/**
 * This file is part of the nmap package.
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @license    MIT License
 */

namespace Nmap\Util;

use Symfony\Component\Process\Process;

/**
 * @author William Durand <william.durand1@gmail.com>
 */
class ProcessExecutor
{

    /**
     * @param string $command The command to execute.
     *
     * @param int    $timeout seconds
     * @return int
     */
    public function execute($command, $timeout = 60)
    {
        $process = new Process($command);

        $process->setTimeout($timeout);

        $process->run();

        if (!$process->isSuccessful()) {
            throw new \RuntimeException(sprintf(
                'Failed to execute "%s"' . PHP_EOL . '%s',
                $command,
                $process->getErrorOutput()
            ));
        }

        return $process->getExitCode();
    }
}
