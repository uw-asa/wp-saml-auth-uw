<?php
/**
 * Plugin Name: WP SAML Auth for UW
 * Version: 1.1.1
 * Description: Autoconfiguration of Pantheon's wp-saml-auth plugin for use at the University of Washington
 * Author: Bradley Bell <bradleyb@uw.edu>
 * Author URI: https://asais.uw.edu
 * Plugin URI: https://github.com/uw-asa/wp-saml-auth-uw
 * Text Domain: wp-saml-auth-uw
 * Domain Path: /languages
 *
 */

define('WP_SAML_AUTH_UW_GROUP_STEM', 'uw_asa_it_web');
define('WP_SAML_AUTH_UW_SP_CERT', ABSPATH . 'private/sp.crt');
define('WP_SAML_AUTH_UW_SP_KEY', ABSPATH . 'private/sp.key');
define('WP_SAML_AUTH_UW_IDP_CERT', ABSPATH . 'private/uw-idp-md-cert.pem');

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
                'x509cert' => @file_get_contents(WP_SAML_AUTH_UW_SP_CERT),
                'privateKey' => @file_get_contents(WP_SAML_AUTH_UW_SP_KEY),
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
                'x509cert' => @file_get_contents(WP_SAML_AUTH_UW_IDP_CERT),
                // Optional: Instead of using the x509 cert, you can specify the fingerprint and algorithm.
                'certFingerprint' => '',
                'certFingerprintAlgorithm' => '',
            ),
            'security'     => array(
                // Indicates whether the <samlp:AuthnRequest> messages sent by this SP
                // will be signed.  [Metadata of the SP will offer this info]
                'authnRequestsSigned' => true,
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
 * remove prefixes and suffixes from the site's domain
 * usually just a single name, but if there are multiple,
 * reverse them and replace dots with underscores.
 * ex: emfinadmin.uw.edu => emfinadmin
 *     kb.registrar.washington.edu => registrar_kb
 */
function site_slug() {
    $domain = parse_url(site_url(), PHP_URL_HOST);

    $domain = preg_replace('/^((dev|test|live)[.-])+/', '', $domain);
    $domain = preg_replace('/\.(dev|test|live)\.cms.+$/', '', $domain);
    $domain = preg_replace('/([.-]asa)?[.-](uw|washington)\.(edu|pantheonsite\.io)$/', '', $domain);

    $parts = explode('.', $domain);
    $site = implode('_', array_reverse($parts));

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

function custom_user_attributes()
{
    return array(
        'uwStudentSystemKey' => array(
            'display_name'   => 'uwStudentSystemKey',
            'saml_attribute' => 'urn:oid:1.2.840.113994.200.20',
        ),
    );
}

/**
 * Add user to roles according to the groups given in attributes
 */
function set_user_roles_and_attributes( $user, $attributes ) {
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

    foreach (custom_user_attributes() as $meta_key => $user_attribute) {
        if (array_key_exists($user_attribute['saml_attribute'], $attributes)) {
            update_user_meta($user->ID, $meta_key, $attributes[$user_attribute['saml_attribute']]);
        } else {
            delete_user_meta($user->ID, $meta_key);
        }
    }
}
add_action( 'wp_saml_auth_existing_user_authenticated', 'set_user_roles_and_attributes', 10, 2);
add_action( 'wp_saml_auth_new_user_authenticated', 'set_user_roles_and_attributes', 10, 2);

function custom_attribute_columns($users_columns)
{
    foreach (custom_user_attributes() as $meta_key => $user_attribute) {
        $users_columns[$meta_key] = $user_attribute['display_name'];
    }

    return $users_columns;
}
add_filter("wpmu_users_columns", "custom_attribute_columns");

function display_custom_attribute($output, $column_name, $uid)
{
    $custom_attributes = array_keys(custom_user_attributes());

    if (!in_array($column_name, $custom_attributes)) {
        return $output;
    }

    return get_user_meta($uid, $column_name, true);
}
add_filter("manage_users_custom_column", "display_custom_attribute", 10, 3);

add_action( 'network_admin_menu', function() {
    add_submenu_page(
        'settings.php',
        __( 'WP SAML Auth UW Settings', 'wp-saml-auth-uw' ),
        __( 'WP SAML Auth UW', 'wp-saml-auth-uw' ),
        'manage_options',
        'wp-saml-auth-uw-settings',
        function() {
            $config = apply_filters( 'wp_saml_auth_option', null, 'internal_config' );
            date_default_timezone_set('America/Los_Angeles');
            ?>
            <div class="wrap">
                <h2><?php esc_html_e( 'WP SAML Auth UW Settings', 'wp-saml-auth-uw' ); ?></h2>
                <h2>Service Provider</h2>
                <p>This service provider must be registered in the UW Service Provider Registry:</p>
                <table class="form-table" role="presentation">
                    <tr><th scope="row">Entity Id</th>
                        <td><tt><?= $config['sp']['entityId'] ?></tt></td>
                    </tr>
                </table>
                <h2>Service Provider Certificate</h2>
<?php $cert = @file_get_contents(WP_SAML_AUTH_UW_SP_CERT); ?>
<?php if ($cert === false): ?>
                <p>Error: Certificate '<?= WP_SAML_AUTH_UW_SP_CERT ?>' could not be read.</p>
<?php else: ?>
                <?php  $cert_data = openssl_x509_parse($cert); ?>
                <p>This certificate must be present in the above SP Registry entry</p>
                <table role="presentation">
<?php  foreach (array('subject', 'issuer') as $attr): ?>
                    <tr><th scope="row"><?= $attr ?></th><td>
                        <?= implode(', ', array_reverse(array_map(function ($k, $v) { return "{$k}={$v}"; }, array_keys($cert_data[$attr]), array_values($cert_data[$attr])))) ?>
                    </td></tr>
<?php  endforeach; ?>
<?php  foreach (array('validFrom', 'validTo') as $attr): ?>
                    <tr><th scope="row"><?= $attr ?></th><td>
                        <?= date('m/d/Y', $cert_data["{$attr}_time_t"]) ?>
                    </td></tr>
<?php  endforeach; ?>
                    <tr><td colspan="2">
                        <textarea cols="70" rows="10" readonly="readonly"><?= $cert ?></textarea>
                    </td></tr>
                </table>
<?php endif; ?>
                <h2>Service Provider Private Key</h2>
<?php $private_key = @file_get_contents(WP_SAML_AUTH_UW_SP_KEY); ?>
<?php if ($private_key === false): ?>
                <p>Error: Private key '<?= WP_SAML_AUTH_UW_SP_KEY ?>' could not be read.</p>
<?php else: ?>
<?php  if (!openssl_x509_check_private_key($cert, $private_key)): ?>
                <p>Error: Private key '<?= WP_SAML_AUTH_UW_SP_KEY ?>' does not match certificate.</p>
<?php  else: ?>
                <p>Private key matches certificate.</p>
<?php  endif; ?>
<?php endif; ?>
                <h2>Identity Provider Certificate</h2>
<?php $cert = @file_get_contents(WP_SAML_AUTH_UW_IDP_CERT); ?>
<?php if ($cert === false): ?>
                <p>Error: Certificate '<?= WP_SAML_AUTH_UW_IDP_CERT ?>' could not be read.</p>
<?php else: ?>
                <?php  $cert_data = openssl_x509_parse($cert); ?>
                <p>This certificate must match the current UW IdP Certificate</p>
                <table role="presentation">
<?php  foreach (array('subject', 'issuer') as $attr): ?>
                    <tr><th scope="row"><?= $attr ?></th><td>
                        <?= implode(', ', array_reverse(array_map(function ($k, $v) { return "{$k}={$v}"; }, array_keys($cert_data[$attr]), array_values($cert_data[$attr])))) ?>
                    </td></tr>
<?php  endforeach; ?>
<?php  foreach (array('validFrom', 'validTo') as $attr): ?>
                    <tr><th scope="row"><?= $attr ?></th><td>
                        <?= date('m/d/Y', $cert_data["{$attr}_time_t"]) ?>
                    </td></tr>
<?php  endforeach; ?>
                    <tr><td colspan="2">
                        <textarea cols="70" rows="10" readonly="readonly"><?= $cert ?></textarea>
                    </td></tr>
                </table>
<?php endif; ?>
                <h2>Assertion Consumer Service URLs</h2>
                <p>Add these to the SP Registry entry, with the binding <tt>urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST</tt></p>
                <table class="form-table" role="presentation">
<?php foreach (get_sites('fields=ids') as $site_id): ?>
                    <tr><th scope="row">location</th>
                        <td><tt><?= site_acs_url($site_id) ?></tt></td></tr>
<?php endforeach; ?>
                </table>
                <h2>Role Mapping</h2>
                <p>Roles are granted or revoked upon login, according to membership in these UW Groups:</p>
                <table class="form-table" role="presentation">
                    <tr><th scope="row">Super Admin</th>
                    <td><tt><?= super_admin_group() ?></tt></td></tr>
                </table>
                <h2>Attribute Mapping</h2>
                <p>Custom attributes will be added to users according to these SAML attributes:</p>
                <table class="form-table" role="presentation">
<?php foreach (custom_user_attributes() as $user_attribute): ?>
                    <tr><th scope="row"><?= $user_attribute['display_name'] ?></th>
                    <td><tt><?= $user_attribute['saml_attribute'] ?></tt></td></tr>
<?php endforeach; ?>
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
