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
     * @param bool $exclude_dev
     *   Exclude_dev option.
     * @param string $expected_status
     *   Expected status of test.
     *
     * @return void
     *
     * @throws \Exception
     */
    public function testChecker($url, $lock, $exclude_dev, $expected_status)
    {
        $composer_lock = file_get_contents($lock);
        $this->assertIsString($composer_lock);

        if (is_string($composer_lock)) {
            $checker = new SecurityChecker([$url]);
            $data = $checker->checkComposer($composer_lock, $exclude_dev);

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
        $data_dir = __DIR__ . '/../data';
        return [
            'drupal-roave' => [
                $data_dir . '/composer-roave.json',
                $data_dir . '/drupal8.8.0/composer.lock',
                false,
                'vulnerable',
            ],
            'symfony-roave' => [
                $data_dir . '/composer-roave.json',
                $data_dir . '/symfony4.3.8/composer.lock',
                false,
                'ok',
            ],
            'dev-vulnerable-roave' => [
                $data_dir . '/composer-roave.json',
                $data_dir . '/dev-vulnerable/composer.lock',
                false,
                'ok',
            ],
            'dev-vulnerable-roave-nodev' => [
                $data_dir . '/composer-roave.json',
                $data_dir . '/dev-vulnerable/composer.lock',
                true,
                'ok',
            ],
            'dev-vulnerable-drupal' => [
                $data_dir . '/composer-drupal.json',
                $data_dir . '/dev-vulnerable/composer.lock',
                false,
                'vulnerable',
            ],
            'dev-vulnerable-drupal-nodev' => [
                $data_dir . '/composer-drupal.json',
                $data_dir . '/dev-vulnerable/composer.lock',
                true,
                'ok',
            ],
        ];
    }
}
