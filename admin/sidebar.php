<?php
/**
 * White-label administrative sidebar shared by the GSMXBOOK legacy admin panel.
 * The scoped styles below intentionally override old page-local sidebar/logo rules
 * so every admin function renders the same logo size and navigation structure.
 */

if (count(get_included_files()) === 1) {
    header("HTTP/1.1 403 Forbidden");
    die("Direct access to layout components is strictly prohibited.");
}

$current_page = basename(parse_url($_SERVER['PHP_SELF'] ?? '', PHP_URL_PATH));
$current_uri  = trim(parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH), '/');

// 🌟 সব মেনুর অ্যাক্টিভ স্টেট ডিটেকশন
$dashboard_active     = ($current_uri === 'admin' || $current_uri === 'admin/' || $current_uri === 'admin/index.php' || $current_page === 'index.php') ? 'active' : '';
$explorer_active      = in_array($current_page, ['explorer.php', 'manage-files.php', 'add-file.php', 'edit_file.php', 'edit_folder.php', 'edit_info.php'], true) ? 'active' : '';
$packages_active      = ($current_page === 'manage_packages.php') ? 'active' : '';
$user_pkgs_active     = ($current_page === 'manage_user_packages.php') ? 'active' : '';
$tutorials_active     = ($current_page === 'manage_tutorials.php') ? 'active' : '';
$gateways_active      = ($current_page === 'payment_gateways.php') ? 'active' : '';
$customizer_active    = ($current_page === 'site_customizer.php') ? 'active' : '';

$auto_pay_active      = ($current_page === 'auto_payments.php') ? 'active' : '';
$manual_pay_active    = in_array($current_page, ['manual_payments.php', 'payment_requests.php'], true) ? 'active' : '';
$purchases_active     = ($current_page === 'file_purchases.php') ? 'active' : '';
$avail_bal_active     = ($current_page === 'user_available_balance.php') ? 'active' : '';
$income_active        = ($current_page === 'income_statement.php') ? 'active' : '';

$users_active         = in_array($current_page, ['manage_users.php', 'process_user.php'], true) ? 'active' : '';
$never_active_page    = ($current_page === 'never_active_users.php') ? 'active' : '';

// 🚀 নতুন ৫টি ফিচারের অ্যাক্টিভ ভেরিয়েবল:
$download_logs_active = ($current_page === 'download_logs.php') ? 'active' : '';
$notices_active       = ($current_page === 'site_notices.php') ? 'active' : '';
$coupons_active       = ($current_page === 'manage_coupons.php') ? 'active' : '';
$login_logs_active    = ($current_page === 'login_logs.php') ? 'active' : '';
$backup_active        = ($current_page === 'db_backup.php') ? 'active' : '';
?>
<style id="gsmx-admin-sidebar-normalizer">
    .gsmx-admin-sidebar.sidebar {
        width: 250px !important;
        min-width: 250px !important;
        background: #0f172a !important;
        color: #94a3b8 !important;
        padding: 0 0 20px !important;
        display: flex !important;
        flex-direction: column !important;
        align-items: stretch !important;
        flex-shrink: 0 !important;
        border-right: 1px solid #1f2937 !important;
        overflow: hidden !important;
    }
    .gsmx-admin-sidebar .sidebar-logo-container.gsmx-admin-brand {
        width: 100% !important;
        min-height: 126px !important;
        margin: 0 !important;
        padding: 15px 14px 13px !important;
        border-bottom: 1px solid #1f2937 !important;
        background: linear-gradient(135deg, #111827 0%, #1e1b4b 100%) !important;
        display: flex !important;
        flex-direction: column !important;
        align-items: center !important;
        justify-content: center !important;
        gap: 7px !important;
        text-align: center !important;
    }
    .gsmx-admin-sidebar .sidebar-logo {
        width: 58px !important;
        height: 58px !important;
        min-width: 58px !important;
        min-height: 58px !important;
        max-width: 58px !important;
        max-height: 58px !important;
        object-fit: contain !important;
        object-position: center !important;
        background: #ffffff !important;
        padding: 2px !important;
        margin: 0 !important;
        border-radius: 50% !important;
        border: 2px solid #38bdf8 !important;
        box-shadow: 0 0 16px rgba(56,189,248,.28) !important;
        display: block !important;
        flex: 0 0 58px !important;
    }
    .gsmx-admin-sidebar .gsmx-admin-brand-name {
        width: 100% !important;
        color: #f8fafc !important;
        font-size: 14px !important;
        line-height: 1.2 !important;
        font-weight: 800 !important;
        letter-spacing: .5px !important;
        overflow: hidden !important;
        text-overflow: ellipsis !important;
        white-space: nowrap !important;
    }
    .gsmx-admin-sidebar .gsmx-admin-brand-subtitle {
        width: 100% !important;
        color: #7dd3fc !important;
        font-size: 9px !important;
        line-height: 1.2 !important;
        font-weight: 800 !important;
        letter-spacing: .7px !important;
        text-transform: uppercase !important;
        overflow: hidden !important;
        text-overflow: ellipsis !important;
        white-space: nowrap !important;
    }
    .gsmx-admin-sidebar .sidebar-menu {
        list-style: none !important;
        width: 100% !important;
        margin: 14px 0 0 !important;
        padding: 0 !important;
        display: block !important;
    }
    .gsmx-admin-sidebar .sidebar-menu li {
        width: 100% !important;
        margin: 0 !important;
        padding: 0 !important;
    }
    .gsmx-admin-sidebar .sidebar-menu li a {
        min-height: 42px !important;
        display: flex !important;
        align-items: center !important;
        justify-content: flex-start !important;
        gap: 11px !important;
        padding: 10px 20px !important;
        color: #94a3b8 !important;
        border-left: 4px solid transparent !important;
        border-bottom: 0 !important;
        border-radius: 0 !important;
        background: transparent !important;
        font-size: 13px !important;
        line-height: 1.25 !important;
        font-weight: 650 !important;
        text-decoration: none !important;
        transition: background .2s ease, color .2s ease, border-color .2s ease !important;
        white-space: nowrap !important;
    }
    .gsmx-admin-sidebar .sidebar-menu li a i {
        width: 20px !important;
        min-width: 20px !important;
        margin: 0 !important;
        text-align: center !important;
        justify-content: center !important;
        font-size: 14px !important;
    }
    .gsmx-admin-sidebar .sidebar-menu li.active > a,
    .gsmx-admin-sidebar .sidebar-menu li > a:hover {
        background: #1e293b !important;
        color: #38bdf8 !important;
        border-left-color: #38bdf8 !important;
    }
    .gsmx-admin-sidebar .sidebar-menu li.active > a i,
    .gsmx-admin-sidebar .sidebar-menu li > a:hover i { color: #38bdf8 !important; }
    
    .gsmx-admin-sidebar .gsmx-customizer-link > a {
        margin-top: 5px !important;
        border-top: 1px solid rgba(56,189,248,.12) !important;
        border-bottom: 1px solid rgba(56,189,248,.12) !important;
    }
    .gsmx-admin-sidebar .gsmx-menu-badge {
        margin-left: auto !important;
        padding: 2px 6px !important;
        border: 1px solid rgba(16,185,129,.35) !important;
        border-radius: 999px !important;
        background: rgba(16,185,129,.12) !important;
        color: #6ee7b7 !important;
        font-size: 8px !important;
        line-height: 1.25 !important;
        font-weight: 900 !important;
        letter-spacing: .5px !important;
    }

    /* 📱 Mobile Responsive View */
    @media (max-width: 768px) {
        .gsmx-admin-sidebar.sidebar {
            width: 100% !important;
            min-width: 100% !important;
            padding: 0 0 10px !important;
            border-right: 0 !important;
            border-bottom: 1px solid #1f2937 !important;
        }
        .gsmx-admin-sidebar .sidebar-logo-container.gsmx-admin-brand {
            min-height: 70px !important;
            padding: 8px 12px !important;
            flex-direction: row !important;
            gap: 10px !important;
        }
        .gsmx-admin-sidebar .sidebar-logo {
            width: 46px !important;
            height: 46px !important;
            min-width: 46px !important;
            min-height: 46px !important;
            max-width: 46px !important;
            max-height: 46px !important;
            flex-basis: 46px !important;
        }
        .gsmx-admin-sidebar .gsmx-admin-brand-copy { min-width: 0 !important; text-align: left !important; }
        .gsmx-admin-sidebar .sidebar-menu {
            margin-top: 8px !important;
            padding: 0 8px !important;
            display: flex !important;
            gap: 7px !important;
            overflow-x: auto !important;
            flex-wrap: nowrap !important;
            scrollbar-width: thin !important;
            -webkit-overflow-scrolling: touch;
        }
        .gsmx-admin-sidebar .sidebar-menu li { width: auto !important; flex: 0 0 auto !important; }
        .gsmx-admin-sidebar .sidebar-menu li a {
            min-height: 38px !important;
            padding: 9px 12px !important;
            border: 1px solid #334155 !important;
            border-left: 1px solid #334155 !important;
            border-radius: 8px !important;
            background: #1e293b !important;
            font-size: 11px !important;
        }
        .gsmx-admin-sidebar .sidebar-menu li.active > a,
        .gsmx-admin-sidebar .sidebar-menu li > a:hover {
            border-color: #38bdf8 !important;
            color: #38bdf8 !important;
        }
        .gsmx-admin-sidebar .gsmx-customizer-link > a { margin-top: 0 !important; }
    }
</style>

<div class="sidebar gsmx-admin-sidebar">
    <div class="sidebar-logo-container gsmx-admin-brand">
        <img src="<?php echo htmlspecialchars(gsmx_site_asset('site_logo'), ENT_QUOTES, 'UTF-8'); ?>" alt="<?php echo gsmx_site_e('site_name'); ?> Logo" class="sidebar-logo">
        <div class="gsmx-admin-brand-copy">
            <div class="gsmx-admin-brand-name"><?php echo gsmx_site_e('site_name'); ?></div>
            <div class="gsmx-admin-brand-subtitle"><?php echo gsmx_site_e('admin_panel_name'); ?></div>
        </div>
    </div>
    <ul class="sidebar-menu">
        <li class="<?php echo $dashboard_active; ?>"><a href="/admin"><i class="fa-solid fa-gauge" style="color:#93c5fd;"></i> Dashboard</a></li>
        <li class="<?php echo $explorer_active; ?>"><a href="/admin/explorer.php"><i class="fa-solid fa-folder-tree" style="color:#93c5fd;"></i> Step Explorer (Files)</a></li>
        <li class="<?php echo $packages_active; ?>"><a href="/admin/manage_packages.php"><i class="fa-solid fa-box-open" style="color:#93c5fd;"></i> Package Manager</a></li>
        <li class="<?php echo $user_pkgs_active; ?>"><a href="/admin/manage_user_packages.php"><i class="fa-solid fa-users-gear" style="color:#93c5fd;"></i> User Packages</a></li>
        <li class="<?php echo $tutorials_active; ?>"><a href="/admin/manage_tutorials.php"><i class="fa-solid fa-graduation-cap" style="color:#93c5fd;"></i> Tutorial Manager</a></li>
        <li class="<?php echo $gateways_active; ?>"><a href="/admin/payment_gateways.php"><i class="fa-solid fa-credit-card" style="color:#93c5fd;"></i> Payment Gateways</a></li>
        <li class="<?php echo $customizer_active; ?> gsmx-customizer-link"><a href="/admin/site_customizer.php"><i class="fa-solid fa-wand-magic-sparkles" style="color:#93c5fd;"></i> Website Customizer <span class="gsmx-menu-badge">SITE</span></a></li>
        
        <!-- ⚡ Auto Payments -->
        <li class="<?php echo $auto_pay_active; ?>"><a href="/admin/auto_payments.php"><i class="fa-solid fa-bolt" style="color: #14b8a6;"></i> Auto Payments</a></li>
        
        <!-- 💳 Manual Payments -->
        <li class="<?php echo $manual_pay_active; ?>"><a href="/admin/manual_payments.php"><i class="fa-solid fa-money-bill-transfer" style="color: #f43f5e;"></i> Manual Payments</a></li>
        
        <!-- 🛒 File Purchases -->
        <li class="<?php echo $purchases_active; ?>"><a href="/admin/file_purchases.php"><i class="fa-solid fa-cart-shopping" style="color: #38bdf8;"></i> File Purchases</a></li>
        
        <!-- 💰 User Available Balance -->
        <li class="<?php echo $avail_bal_active; ?>"><a href="/admin/user_available_balance.php"><i class="fa-solid fa-wallet" style="color: #10b981;"></i> User Available Balance</a></li>
        
        <!-- 📊 Income Statement -->
        <li class="<?php echo $income_active; ?>"><a href="/admin/income_statement.php"><i class="fa-solid fa-chart-pie" style="color: #38bdf8;"></i> Income Statement</a></li>

        <!-- 👥 Users Manager -->
        <li class="<?php echo $users_active; ?>"><a href="/admin/manage_users.php"><i class="fa-solid fa-users" style="color: #38bdf8;"></i> Users Manager</a></li>

        <!-- ⏳ Never Active Users -->
        <li class="<?php echo $never_active_page; ?>"><a href="/admin/never_active_users.php"><i class="fa-solid fa-user-clock" style="color: #fbbf24;"></i> Never Active Users</a></li>

        <!-- 🚀 নতুন ৫টি ফাংশন -->
        <!-- ১. Download Logs -->
        <li class="<?php echo $download_logs_active; ?>"><a href="/admin/download_logs.php"><i class="fa-solid fa-cloud-arrow-down" style="color: #38bdf8;"></i> Download Logs</a></li>

        <!-- ২. Notice & Pop-ups -->
        <li class="<?php echo $notices_active; ?>"><a href="/admin/site_notices.php"><i class="fa-solid fa-bullhorn" style="color: #f59e0b;"></i> Notice & Pop-ups</a></li>

        <!-- ৩. Coupon & Promo Manager -->
        <li class="<?php echo $coupons_active; ?>"><a href="/admin/manage_coupons.php"><i class="fa-solid fa-ticket" style="color: #ec4899;"></i> Coupon & Discounts</a></li>

        <!-- ৪. Login & Security Audit Logs -->
        <li class="<?php echo $login_logs_active; ?>"><a href="/admin/login_logs.php"><i class="fa-solid fa-shield-halved" style="color: #818cf8;"></i> Login & Security Logs</a></li>

        <!-- ৫. One-Click Database Backup -->
        <li class="<?php echo $backup_active; ?>"><a href="/admin/db_backup.php"><i class="fa-solid fa-database" style="color: #10b981;"></i> Database Backup</a></li>

        <li><a href="/" target="_blank" rel="noopener"><i class="fa-solid fa-globe" style="color: #93c5fd;"></i> Open Live Site</a></li>
    </ul>
</div>