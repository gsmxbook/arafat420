<?php
/**
 * GSMXBOOK Unified Admin Dashboard Footer Wrapper
 * Hardened against direct routing info leakage & optimized for sticky flexbox layouts
 */

// 🛡️ [DIRECT ACCESS FIREWALL]: Prevent unauthorized direct browser execution of this component
if (count(get_included_files()) === 1) {
    header("HTTP/1.1 403 Forbidden");
    die("Direct access to layout components is strictly prohibited.");
}
?>
<style>
    /* ========================================================
       🌐 UNIFIED ADMIN DASHBOARD FOOTER WRAPPER SPECIFICATIONS
       ======================================================== */
    .dashboard-footer-wrapper {
        width: 100%;
        margin-top: auto; /* Pushes the footer to the bottom even if the viewport content is minimal */
        padding: 0;
        background-color: #0f172a; /* Matching with the admin dark theme color specifications */
        position: relative;
        z-index: 10;
    }
    
    /* Margin and border alignment configurations for the admin panel footer context */
    .dashboard-footer-wrapper .footer-container {
        margin-top: 0 !important; 
        border-top: 1px solid #1f2937 !important;
        background-color: #0f172a !important;
        padding: 20px 25px !important;
    }

    /* 📱 Responsive padding adjustment for administrative mobile viewports */
    @media (max-width: 768px) {
        .dashboard-footer-wrapper .footer-container {
            padding: 15px 12px !important;
            text-align: center;
        }
    }
</style>

<div class="dashboard-footer-wrapper">
    <?php 
    // ✅ [PATH COMPATIBILITY ENGINE]: Dynamically checks both directory tree scopes to prevent missing resource exceptions
    if (file_exists('footer.php')) { 
        include 'footer.php'; 
    } elseif (file_exists('../footer.php')) { 
        include '../footer.php'; 
    } 
    ?>
</div>