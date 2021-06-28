<?php

namespace Ows\ComposerDependenciesSecurityChecker;

use Composer\Semver\Semver;
use Exception;

/**
 * Service to check the security state of a project from a composer.lock file.
 *
 * Checks performed against the **conflict** section of a composer.json file,
 * like the one from this repo: https://github.com/Roave/SecurityAdvisories.
 */
class SecurityChecker
{

    /**
     * A list of security advisories urls of composer.json files.
     *
     * @var array
     */
    protected $urlsAdvisories = ['https://raw.githubusercontent.com/Roave/SecurityAdvisories/master/composer.json'];

    /**
     * Static cache for data of each security advisories url.
     *
     * @var array
     */
    protected static $urlsComposerAdvisoriesData;

    /**
     * @param array $urls_advisories
     *   A list of security advisories urls.
     */
    public function __construct(array $urls_advisories = [])
    {
        if (!empty($urls_advisories)) {
            $this->urlsAdvisories = $urls_advisories;
        }
    }

    /**
     * Global function to made several checks on a same composer.lock file.
     *
     * @param string $composer_lock
     *   The composer.lock file to check.
     *
     * @return array
     *   An array with the status and the possibles vulnerabilities founded.
     *   The status can be "ok" or "vulnerable" and in this case, vulnerabilities
     *   is an array with each vulnerability (array: name, version, links).
     *
     * @throws \Exception
     */
    public function checkComposer($composer_lock)
    {
        $vulnerabilities = [];
        $status = 'ok';

        $composer_lock_data = json_decode($composer_lock, true);
        foreach ($this->urlsAdvisories as $url) {
            $security_advisories_composer_json = $this->fetchAdvisoryComposerJson($url);
            $updates = $this->calculateSecurityUpdates(
                $composer_lock_data,
                $security_advisories_composer_json
            );
            if (!empty($updates)) {
                $vulnerabilities += $updates;
                $status = 'vulnerable';
            }
        }

        return ['status' => $status, 'vulnerabilities' => $vulnerabilities];
    }

    /**
     * Fetches the generated composer.json from a security-advisory.
     *
     * @param string $url
     *   Url of composer.json of the security-advisory.
     *
     * @return array
     *   Data decoded from the composer.json.
     *
     * @throws \Exception
     */
    protected function fetchAdvisoryComposerJson($url)
    {
        if (!isset(static::$urlsComposerAdvisoriesData[$url])) {
            $response = file_get_contents($url);
            if ($response) {
                $security_advisories = json_decode($response, true);
            } else {
                $security_advisories = false;
            }

            static::$urlsComposerAdvisoriesData[$url] = $security_advisories;
        }

        if (empty(static::$urlsComposerAdvisoriesData[$url])) {
            throw new Exception(
                "Unable to fetch security-advisories information from $url."
            );
        }

        return static::$urlsComposerAdvisoriesData[$url];
    }

    /**
     * Return available security updates.
     *
     * @param array $composer_lock_data
     *   The contents of a composer.lock file.
     * @param array $security_advisories_composer_json
     *   The composer.json array from the security-advisory.
     *
     * @return array
     *   Security updates availables, keyed by package name,
     *   with those informations:
     *   - name
     *   - version
     *   - links.
     */
    protected function calculateSecurityUpdates(array $composer_lock_data, array $security_advisories_composer_json, bool $excludeDev = false)
    {
        if ($excludeDev) {
            $packages = $composer_lock_data['packages-dev'];
        }
        else {
            $packages = array_merge(
                $composer_lock_data['packages-dev'],
                $composer_lock_data['packages']
            );
        }
        $updates = [];
        $conflict = $security_advisories_composer_json['conflict'];
        foreach ($packages as $package) {
            $name = $package['name'];
            $version = $package['version'];
            if (empty($conflict[$name]) || !Semver::satisfies($version, $conflict[$name])) {
                continue;
            }

            if (mb_strpos($package['type'], 'drupal-') === 0) {
                if ($name == 'drupal/core') {
                    $module_name = 'drupal';
                } else {
                    $module_name = str_replace('drupal/', '', $name);
                    $version = $package['source']['reference'];
                }

                $title = $module_name . ' : Version ' . $version;
                $link = "https://www.drupal.org/project/$module_name/releases/" . $version;
            } else {
                $title = $name . ' : Version ' . $version;
                $link = "https://packagist.org/packages/$name#" . $version;
            }

            $updates[$name] = [
                'name' => $name,
                'version' => $version,
                'links' => [
                    [
                        'title' => $title,
                        'link' => $link,
                    ],
                ],
            ];
        }
        return $updates;
    }
}
