<?php

namespace Ows\ComposerDependenciesSecurityChecker\Tests;

use Ows\ComposerDependenciesSecurityChecker\SecurityChecker;
use PHPUnit\Framework\TestCase;

/**
 * Tests.
 */
class SecurityCheckerTest extends TestCase
{

    /**
     * Basic tests.
     *
     * @dataProvider dataProvider
     *
     * @param string $url
     *   Url of composer.json containing security advisories.
     * @param string $lock
     *   Url of composer.lock to check.
     * @param string $expected_status
     *   Expected status of test.
     *
     * @return void
     *
     * @throws \Exception
     */
    public function testChecker($url, $lock, $expected_status)
    {
        $composer_lock = file_get_contents($lock);
        $this->assertIsString($composer_lock);

        if (is_string($composer_lock)) {
            $checker = new SecurityChecker([$url]);
            $data = $checker->checkComposer($composer_lock);

            $this->assertArrayHasKey('status', $data);

            $this->assertEquals($expected_status, $data['status']);
        }
    }

    /**
     * Data for testing.
     *
     * @return array
     *   Trios of:
     *   - Url of composer.json containing security advisories,
     *   - Url of composer.lock to check,
     *   - Expected status.
     */
    public function dataProvider()
    {
        return [
            [
                __DIR__ . '/../composer.json',
                __DIR__ . '/../data/drupal8.8.0/composer.lock',
                'vulnerable',
            ],
            [
                __DIR__ . '/../composer.json',
                __DIR__ . '/../data/symfony4.3.8/composer.lock',
                'ok',
            ],
        ];
    }
}
