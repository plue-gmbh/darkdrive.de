<?php
/**
 * Darkdrive
 * Securely Encrypted Private Cloud
 * https://darkdrive.de
 *
 * Copyright © 2026 plue GmbH
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * https://plue.tech
 *
 * This file is excluded from automatic updates — safe to customize per installation.
 */

date_default_timezone_set('Europe/Berlin');

ini_set('memory_limit', '2048M'); // 2 GB headroom for the chunked upload buffer (16 MB chunks, encrypted in memory)
ini_set('max_execution_time', '300');
ini_set('default_socket_timeout', '300');

define('DARKDRIVE_TITLE', 'Darkdrive');
define('DARKDRIVE_MAX_FILESIZE', 1024*2); // MB — max upload size (2 GB)
define('DARKDRIVE_MAX_STORAGE', 1024*100); // MB — total storage limit (100 GB)

// define('DARKDRIVE_STORAGE_DIR', '/home/my_data'); // data directory outside the webroot

// define('DARKDRIVE_S3_ENDPOINT', '');
// define('DARKDRIVE_S3_BUCKET', '');
// define('DARKDRIVE_S3_ACCESS_KEY', '');
// define('DARKDRIVE_S3_SECRET_KEY', '');
// define('DARKDRIVE_S3_REGION', '');
// define('DARKDRIVE_S3_MAX_STORAGE', 1024*1024); // MB — S3 storage limit (1 TB)

// define('DARKDRIVE_UPDATE_DELAY', 1); // days to hold new releases: 0 = immediately, INF = never

// define('DARKDRIVE_EMERGENCY_PASSWORD', true); // enables /emergency password re-encryption — disable right after use

require_once 'components/app.class.php';

new App();