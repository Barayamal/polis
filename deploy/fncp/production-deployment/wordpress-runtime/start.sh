#!/bin/sh
set -eu
umask 077
php /opt/fncp-wordpress/preflight.php
exec apache2-foreground
