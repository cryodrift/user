<?php

//declare(strict_types=1);

/**
 * @composer pragmarx/google2fa
 * @env USER_USEAUTH=true
 * @env USER_HTTPS=true
 * @env USER_COOKIEPASSWORD="-secret=put user_mainkey_here or make a new one"
 * @env USER_MAINKEY="RUN: php vendor/bin/cryodrift.php /user/cli keygen || RUN: php index.php /user/cli keygen"
 * @env USER_USE2FA=false
 * @env USER_HIDELOGIN=true
 * @env USER_AUTHDIR="G_ROOTDIR.cryodrift/auth/"
 * @env USER_AUTHCOMPANY="localdev"
 * @env USER_AUTHPASSLEN=6
 * @env USER_STORAGEDIRS="G_ROOTDIR.cryodrift/users/"
 * @env USER_TIMEOUT="120"
 */

use cryodrift\fw\Core;

if (!isset($ctx)) {
    $ctx = Core::newContext(new \cryodrift\fw\Config());
}

$cfg = $ctx->config();

$cfg[\cryodrift\user\Web::class] = \cryodrift\user\Cli::class;
$cfg[\cryodrift\user\Cli::class] = [
  'templatepath' => __DIR__ . '/ui/main.html',
  'company' => Core::env('USER_AUTHCOMPANY'),
  'passwordlen' => Core::env('USER_AUTHPASSLEN'),
  'storagedir' => Core::env('USER_SDIR'),
  'secretkey' => Core::env('USER_MAINKEY'),
  'cookiepassword' => Core::env('USER_COOKIEPASSWORD'),
  'timeout' => Core::env('USER_TIMEOUT'),
  'title' => 'Settings',
  'description' => 'User Settings',
  'langcode' => 'de',
  'use2fa' => Core::env('USER_USE2FA'),
  'hidelogin' => Core::env('USER_HIDELOGIN'),
  'https' => Core::env('USER_HTTPS'),
  'componenthandler' => \cryodrift\user\Web::class,
  'components' => [
    'index',
  ],
];

$cfg[\cryodrift\user\db\Repository::class] = [
  'storagedir' => Core::env('USER_AUTHDIR'),
];

$cfg[\cryodrift\user\AccountStorage::class] = [
  'storagedir' => Core::env('USER_STORAGEDIRS'),
];

if (Core::env('USER_USEAUTH')) {
    $cfg->addHandlerbefore(\cryodrift\fw\ResponseCache::class, \cryodrift\user\Auth::class, [
      'cookiepassword' => Core::env('USER_COOKIEPASSWORD'),
      'https' => Core::env('USER_HTTPS'),
      \cryodrift\user\Auth::CONFIG_NEEDUSER => [
        'user/api',
        'user/name'
      ],
      \cryodrift\user\Auth::CONFIG_USESESSION => []
    ]);
}

\cryodrift\fw\Router::addConfigs($ctx, [
  'user/cli' => \cryodrift\user\Cli::class,
], \cryodrift\fw\Router::TYP_CLI);

\cryodrift\fw\Router::addConfigs($ctx, [
  'user' => \cryodrift\user\Web::class,
  '/' => [[\cryodrift\user\Web::class, 'index']]
], \cryodrift\fw\Router::TYP_WEB);
