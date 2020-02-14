# Composer dependencies security checker

[![Build Status](https://api.travis-ci.org/OWS/composer-dependencies-security-checker.svg?branch=master)](https://travis-ci.org/OWS/composer-dependencies-security-checker)

This library checks a composer.lock file to find existing security advisories published in a composer.json having the **conflict** property filled like https://github.com/Roave/SecurityAdvisories does.

This one is the default used if none passed in constructor.

## Installation

This project can be installed with [Composer](https://getcomposer.org/):

``` bash
$ composer require ows/composer-dependencies-security-checker
```

## Usage

```php
$checker = new Ows\ComposerDependenciesSecurityChecker\SecurityChecker();
$data = $checker->checkComposer(file_get_contents('composer.lock'));
if ($data['status'] == 'vulnerable') {
    foreach ($data['vulnerabilities'] as $package => $infos) {
        echo "{$package} ({$infos['version']}):\n";
        foreach ($infos['links'] as $link) {
            echo "{$link['title']}: {$link['link']}\n";
        }
    }
}
```

## Sources

This library extracts data from https://github.com/Roave/SecurityAdvisories and
indirectly from https://github.com/FriendsOfPHP/security-advisories.
