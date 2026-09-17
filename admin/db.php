<?php
/**
 * GSMXBOOK Admin Core Database Bridge Proxy Configuration
 * Hardened against direct routing execution and path-traversal anomalies
 */

// 🛡️ [DIRECT ACCESS FIREWALL]: Prevent unauthorized direct browser execution of this bridge component
if (count(get_included_files()) === 1) {
    header("HTTP/1.1 403 Forbidden");
    die("Direct access to core configuration nodes is strictly prohibited.");
}

// ✅ Securely include the core database configuration layer from the root directory exactly once using absolute directory mapping
include_once __DIR__ . '/../db.php';
?>