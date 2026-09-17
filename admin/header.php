<?php
/**
 * GSMXBOOK Administrative Unified Top Navbar Header Component
 * Hardened against direct routing access leaks and enhanced with dynamic session indicators
 */

// 🛡️ [BULLETPROOF DIRECT ACCESS FIREWALL]: সরাসরি ব্রাউজার থেকে ফাইল অ্যাক্সেস করা সম্পূর্ণ নিষিদ্ধকরণ
if (count(get_included_files()) === 1 || basename($_SERVER['SCRIPT_FILENAME']) === basename(__FILE__)) {
    header("HTTP/1.1 403 Forbidden");
    header("Status: 403 Forbidden");
    die("Direct access to layout components is strictly prohibited.");
}

// 🟢 [DYNAMIC SESSION RESOLVER]: সেশন থেকে অ্যাডমিনের নাম সেফলি রিড করা
$display_admin_name = 'gsmxbook';
if (isset($_SESSION['username']) && !empty($_SESSION['username'])) {
    $display_admin_name = $_SESSION['username'];
} elseif (isset($_SESSION['temp_admin_username']) && !empty($_SESSION['temp_admin_username'])) {
    $display_admin_name = $_SESSION['temp_admin_username'];
}

// CSRF ভ্যালিডেশন শক্তিশালী করার জন্য টোকেন ম্যাপিং (যদি সেশনে জেনারেট করা থাকে)
$nav_csrf_param = "";
if (!empty($_SESSION['admin_login_csrf'])) {
    $nav_csrf_param = "&token=" . urlencode($_SESSION['admin_login_csrf']);
}
?>
<style>
    /* ========================================================
        🌐 UNIFIED ADMIN TOP NAVBAR GLOBAL SPECIFICATIONS
       ======================================================== */
    .top-navbar { 
        background-color: #0f172a; /* Premium Admin Dark Theme */
        height: 60px; 
        display: flex; 
        justify-content: space-between; 
        align-items: center; 
        padding: 0 30px; 
        border-bottom: 1px solid #1f2937; 
        width: 100%;
        box-sizing: border-box;
    }
    
    .admin-profile-info {
        font-size: 14px;
        font-weight: 600;
        color: #cbd5e1;
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .admin-profile-info i {
        color: #38bdf8; /* Cyan Icon Theme */
        font-size: 16px;
    }
    
    .btn-logout-panel {
        background-color: #1f2937; 
        color: #f87171; 
        padding: 6px 14px; 
        border-radius: 6px; 
        font-size: 13px; 
        font-weight: 700; 
        display: inline-flex; 
        align-items: center; 
        gap: 6px; 
        transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1); 
        border: 1px solid #7f1d1d;
        text-decoration: none;
        cursor: pointer;
    }
    .btn-logout-panel:hover {
        background-color: rgba(127, 29, 29, 0.2); 
        color: #ef4444;
        border-color: #ef4444;
        transform: translateY(-1px);
        box-shadow: 0 0 10px rgba(239, 68, 68, 0.15);
    }

    /* ========================================================
        ✅ [MOBILE FIX]: LAYER CONVERSION FOR SMALL SMARTPHONES
       ======================================================== */
    @media (max-width: 768px) {
        .top-navbar {
            flex-direction: column;
            height: auto;
            padding: 12px 15px;
            gap: 10px;
            text-align: center;
            border-bottom: 1px solid #1f2937;
        }
        .admin-profile-info {
            font-size: 13px;
            justify-content: center;
        }
        .btn-logout-panel {
            width: 100%;
            justify-content: center;
            padding: 9px;
            font-size: 12.5px;
            border-radius: 6px;
        }
    }
</style>
<?php echo gsmx_site_theme_css('admin'); ?>

<div class="top-navbar">
    <div class="admin-profile-info">
        <i class="fa-solid fa-user-gear"></i> <?php echo gsmx_site_e('admin_panel_name'); ?> &mdash; <?php echo htmlspecialchars($display_admin_name, ENT_QUOTES, 'UTF-8'); ?>
    </div>
    <div>
        <!-- CSRF প্রটেকশন প্যারামিটার সহ সুরক্ষিত লগআউট গেটওয়ে লিংক -->
        <a href="/admin/admin_login.php?action=logout<?php echo $nav_csrf_param; ?>" class="btn-logout-panel" onclick="return confirm('Are you sure you want to log out from the admin control panel?')">
            <i class="fa-solid fa-sign-out-alt"></i> Logout
        </a>
    </div>
</div>

<script>
(function () {
    // ৩০ মিনিটের ব্যাকএন্ড আইডল লিমিটের সাথে সামঞ্জস্যপূর্ণ ক্লায়েন্ট-সাইড টাইমআউট
    var ADMIN_IDLE_TIMEOUT_MS = 30 * 60 * 1000;
    var idleTimer = null;

    function scheduleAdminIdleLogout() {
        window.clearTimeout(idleTimer);
        idleTimer = window.setTimeout(function () {
            window.location.href = "/admin/admin_login.php?timeout=idle";
        }, ADMIN_IDLE_TIMEOUT_MS);
    }

    ["click", "keydown", "mousemove", "scroll", "touchstart"].forEach(function (eventName) {
        window.addEventListener(eventName, scheduleAdminIdleLogout, { passive: true });
    });

    scheduleAdminIdleLogout();
})();
</script>