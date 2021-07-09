<?php
/**
 * Plugin Name: WP SAML Auth for UW
 * Version: 1.0.0
 * Description: Autoconfiguration of Pantheon's wp-saml-auth plugin for use at the University of Washington
 * Author: Bradley Bell <bradleyb@uw.edu>
 * Author URI: https://www.washington.edu/asa/
 * Plugin URI: https://github.com/uw-asa/wp-saml-auth-uw
 * Text Domain: wp-saml-auth-uw
 * Domain Path: /languages
 *
 */

define('WP_SAML_AUTH_UW_GROUP_STEM', 'uw_asa_it_web');

function wpsax_filter_option( $value, $option_name ) {
    $defaults = array(
        // Use the OneLogin bundled library
        'connection_type' => 'internal',
        // Configuration options for OneLogin library use.
        'internal_config'        => array(
            // Validation of SAML responses is required.
            'strict'       => true,
            'debug'        => defined( 'WP_DEBUG' ) && WP_DEBUG ? true : false,
            'baseurl'      => home_url(),
            'sp'           => array(
                'entityId' => network_entityid(),
                'assertionConsumerService' => array(
                    'url'  => site_acs_url(),
                    'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                ),
                'x509cert' => file_get_contents(ABSPATH . 'private/sp.crt'),
                'privateKey' => file_get_contents(ABSPATH . 'private/sp.key'),
                // 'x509certNew' => file_get_contents(ABSPATH . 'private/sp-new.crt'),
            ),
            'idp'          => array(
                // Required: Set based on provider's supplied value.
                'entityId' => 'urn:mace:incommon:washington.edu',
                'singleSignOnService' => array(
                    // Required: Set based on provider's supplied value.
                    'url'  => 'https://idp.u.washington.edu/idp/profile/SAML2/Redirect/SSO',
                    'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                ),
                'singleLogoutService' => array(
                    // Required: Set based on provider's supplied value.
                    'url'  => 'https://idp.u.washington.edu/idp/logout',
                    'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                ),
                // Required: Contents of the IDP's public x509 certificate.
                // Use file_get_contents() to load certificate contents into scope.
                'x509cert' => file_get_contents(ABSPATH . 'private/uw-idp-md-cert.pem'),
                // Optional: Instead of using the x509 cert, you can specify the fingerprint and algorithm.
                'certFingerprint' => '',
                'certFingerprintAlgorithm' => '',
            ),
        ),
        // Automatically provision users
        'auto_provision'         => true,
        // Only show login form if parameter is set
        'permit_wp_login'        => ($_GET['saml_sso'] === 'false' ||
                                     $_POST['saml_sso'] === 'false' ? true : false),
        // Map users by login
        'get_user_by'            => 'login',
        // aka 'uid', aka 'uwNetID'
        'user_login_attribute'   => 'urn:oid:0.9.2342.19200300.100.1.1',
        // aka 'mail', aka 'email'
        'user_email_attribute'   => 'urn:oid:0.9.2342.19200300.100.1.3',
        // aka 'cn'
        'display_name_attribute' => 'urn:oid:2.5.4.3',
        // aka 'givenName'
        'first_name_attribute'   => 'urn:oid:2.5.4.42',
        // aka 'surname'
        'last_name_attribute'    => 'urn:oid:2.5.4.4',
        // No default role. Will be added after creation
        'default_role'           => '',
    );
    $value = isset( $defaults[ $option_name ] ) ? $defaults[ $option_name ] : $value;
    return $value;
}
add_filter( 'wp_saml_auth_option', 'wpsax_filter_option', 10, 2 );

add_action( 'login_form', function() {
    if ( $_GET['saml_sso'] === 'false' || $_POST['saml_sso'] === 'false' ) {
        ?><input type="hidden" name="saml_sso" value="false" /><?php
    }
});

/**
 * Don't let admins try to assign roles
 */
function promote_users_cap_filter( $allcaps, $cap, $args ) {
    unset($allcaps['promote_users']);
    return $allcaps;
}
add_filter( 'user_has_cap', 'promote_users_cap_filter', 10, 3 );

/**
 * generate a network-wide entityId
 */
function network_entityid() {
    $entityid = network_site_url('sp');

    /* if this is something other than dev, test, or live, just use the dev entityId. */
    $entityid = preg_replace('/^https:\/\/(?!(?:dev|test|live)-).+-(\w+-asa-uw.*)$/', 'https://dev-$1', $entityid);
    $entityid = preg_replace('/^https:\/\/(?!(?:dev|test|live)\.).+\.(\w+\.asa\.uw\.edu.*)$/', 'https://dev.$1', $entityid);

    return $entityid;
}

/**
 * generate the site's ACS URL
 */
function site_acs_url($site = null) {
    if ($site) {
        switch_to_blog($site);
    }
    $acs_url = site_url('wp-login.php');
    if ($site) {
        restore_current_blog();
    }

    return $acs_url;
}

/**
 * reduce the site down to a single part, removing prefixes etc
 */
function site_slug() {
    $domain = parse_url(site_url(), PHP_URL_HOST);

    $parts = explode('.', $domain);
    $site = array_shift($parts);
    while (preg_match('/^(dev|test)$/', $site)) {
        $site = array_shift($parts);
    }

    if (preg_match('/^\w+-(\w+)-asa-uw$/', $site, $matches)) {
        $site = $matches[1];
    }

    return $site;
}

/**
 * Return an associative array of groups, indexed by role
 */
function site_role_groups() {
    $site_stem = WP_SAML_AUTH_UW_GROUP_STEM.'_'.site_slug();

    $role_map = array();
    foreach (wp_roles()->role_names as $role => $name) {
        $role_map[$role] = $site_stem.'_'.str_replace('_', '-', $role);
    }
    return $role_map;
}

/**
 * Return the super admin group
 */
function super_admin_group() {
    return WP_SAML_AUTH_UW_GROUP_STEM.'_admin';
}

/**
 * Add user to roles according to the groups given in attributes
 */
function add_user_roles( $user, $attributes ) {
    $groups_attribute = 'urn:oid:1.3.6.1.4.1.5923.1.5.1.1';
    if (!($user_groups = $attributes[$groups_attribute])) {
        return;
    }

    if (in_array('urn:mace:washington.edu:groups:' . super_admin_group(), $user_groups)) {
        grant_super_admin($user->ID);
    } else {
        revoke_super_admin($user->ID);
    }

    foreach (site_role_groups() as $role => $uw_group) {
        if (in_array('urn:mace:washington.edu:groups:'.$uw_group, $user_groups)) {
            $user->add_role($role);
        } else {
            $user->remove_role($role);
        }
    }
}
add_action( 'wp_saml_auth_existing_user_authenticated', 'add_user_roles', 10, 2);
add_action( 'wp_saml_auth_new_user_authenticated', 'add_user_roles', 10, 2);

add_action( 'network_admin_menu', function() {
    add_submenu_page(
        'settings.php',
        __( 'WP SAML Auth UW Settings', 'wp-saml-auth-uw' ),
        __( 'WP SAML Auth UW', 'wp-saml-auth-uw' ),
        'manage_options',
        'wp-saml-auth-uw-settings',
        function() {
            $config = apply_filters( 'wp_saml_auth_option', null, 'internal_config' );
            $groups = site_role_groups();
            ?>
            <div class="wrap">
                <h2><?php esc_html_e( 'WP SAML Auth UW Settings', 'wp-saml-auth-uw' ); ?></h2>
                <h2>Service Provider Settings</h2>
                <p>Ensure this metadata is present in the UW Service Provider Registry:</p>
                <table class="form-table" role="presentation">
                    <tr><th scope="row">Entity Id</th>
                        <td><input readonly="readonly" type="text" class="regular-text" value="<?= $config['sp']['entityId'] ?>" /></td></tr>
<?php foreach (get_sites('fields=ids') as $site_id): ?>
                    <tr><th scope="row">Assertion Consumer Service URL</th>
                        <td><input readonly="readonly" type="text" class="regular-text" value="<?= site_acs_url($site_id) ?>" /></td></tr>
<?php endforeach; ?>
                </table>
                <h2>Role Mapping</h2>
                <p>Roles are granted or revoked upon login, according to membership in these UW Groups:</p>
                <table class="form-table" role="presentation">
                    <tr><th scope="row">Super Admin</th>
                    <td><input readonly="readonly" type="text" class="regular-text" value="<?= super_admin_group() ?>" /></td></tr>
                </table>
            </div>
            <?php
        }
    );
});

add_action( 'admin_menu', function() {
    add_submenu_page(
        'users.php',
        __( 'UW User Roles', 'wp-saml-auth-uw' ),
        __( 'UW User Roles', 'wp-saml-auth-uw' ),
        'manage_options',
        'wp-saml-auth-uw-settings',
        function() {
            $config = apply_filters( 'wp_saml_auth_option', null, 'internal_config' );
            $site_stem = WP_SAML_AUTH_UW_GROUP_STEM.'_'.site_slug();
            $groups = site_role_groups();
            ?>
            <div class="wrap">
                <h2><?php esc_html_e( 'UW Groups Required for User Roles', 'wp-saml-auth-uw' ); ?></h2>
                <h2>Role Mapping</h2>
                <p>Roles are granted or revoked upon login, according to membership in these UW Groups:</p>
                <table class="form-table" role="presentation">
<?php foreach (wp_roles()->get_names() as $role => $name): ?>
                    <tr><th scope="row"><?= $name ?></th>
                    <td><a href="https://groups.uw.edu/group/<?= $groups[$role] ?>"><?= $groups[$role] ?></a></td>
                    <td></td></tr>
<?php endforeach; ?>
                </table>
                <a href="https://groups.uw.edu/?view=new&base=<?= $site_stem ?>">Create a group</a>
            </div>
            <?php
        }
    );
});
