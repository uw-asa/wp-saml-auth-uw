<?php
/**
 * Plugin Name: WP SAML Auth for UW
 * Version: 0.0.0
 *
 */

define('WP_SAML_AUTH_UW_GROUP_STEM', 'uw_asa_it_web');

function wpsax_filter_option( $value, $option_name ) {
    $defaults = array(
        /**
         * Type of SAML connection bridge to use.
         *
         * 'internal' uses OneLogin bundled library; 'simplesamlphp' uses SimpleSAMLphp.
         *
         * Defaults to SimpleSAMLphp for backwards compatibility.
         *
         * @param string
         */
        'connection_type' => 'internal',
        /**
         * Configuration options for OneLogin library use.
         *
         * See comments with "Required:" for values you absolutely need to configure.
         *
         * @param array
         */
        'internal_config'        => array(
            // Validation of SAML responses is required.
            'strict'       => true,
            'debug'        => defined( 'WP_DEBUG' ) && WP_DEBUG ? true : false,
            'baseurl'      => home_url(),
            'sp'           => array(
                'entityId' => network_site_url('sp'),
                'assertionConsumerService' => array(
                    'url'  => site_url('wp-login.php'),
                    'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                ),
                // 'x509cert' => file_get_contents(ABSPATH . '/private/sp.crt'),
                // 'privateKey' => file_get_contents(ABSPATH . '/private/sp.key'),
                // 'x509certNew' => file_get_contents(ABSPATH . '/private/sp-new.crt'),
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
                'x509cert' => file_get_contents(ABSPATH . '/private/uw-idp-md-cert.pem'),
                // Optional: Instead of using the x509 cert, you can specify the fingerprint and algorithm.
                'certFingerprint' => '',
                'certFingerprintAlgorithm' => '',
            ),
        ),
        /**
         * Path to SimpleSAMLphp autoloader.
         *
         * Follow the standard implementation by installing SimpleSAMLphp
         * alongside the plugin, and provide the path to its autoloader.
         * Alternatively, this plugin will work if it can find the
         * `SimpleSAML_Auth_Simple` class.
         *
         * @param string
         */
        'simplesamlphp_autoload' => dirname( __FILE__ ) . '/simplesamlphp/lib/_autoload.php',
        /**
         * Authentication source to pass to SimpleSAMLphp
         *
         * This must be one of your configured identity providers in
         * SimpleSAMLphp. If the identity provider isn't configured
         * properly, the plugin will not work properly.
         *
         * @param string
         */
        'auth_source'            => 'default-sp',
        /**
         * Whether or not to automatically provision new WordPress users.
         *
         * When WordPress is presented with a SAML user without a
         * corresponding WordPress account, it can either create a new user
         * or display an error that the user needs to contact the site
         * administrator.
         *
         * @param bool
         */
        'auto_provision'         => true,
        /**
         * Whether or not to permit logging in with username and password.
         *
         * If this feature is disabled, all authentication requests will be
         * channeled through SimpleSAMLphp.
         *
         * @param bool
         */
        'permit_wp_login'        => ($_GET['saml_sso'] === 'false' ? true : false),
        /**
         * Attribute by which to get a WordPress user for a SAML user.
         *
         * @param string Supported options are 'email' and 'login'.
         */
        'get_user_by'            => 'login',
        /**
         * SAML attribute which includes the user_login value for a user.
         *
         * @param string
         */
        'user_login_attribute'   => 'urn:oid:0.9.2342.19200300.100.1.1', // 'uid', 'uwNetID'
        /**
         * SAML attribute which includes the user_email value for a user.
         *
         * @param string
         */
        'user_email_attribute'   => 'urn:oid:0.9.2342.19200300.100.1.3', // 'mail', 'email'
        /**
         * SAML attribute which includes the display_name value for a user.
         *
         * @param string
         */
        'display_name_attribute' => 'urn:oid:2.5.4.3', // 'cn'
        /**
         * SAML attribute which includes the first_name value for a user.
         *
         * @param string
         */
        'first_name_attribute' => 'urn:oid:2.5.4.42', // 'givenName'
        /**
         * SAML attribute which includes the last_name value for a user.
         *
         * @param string
         */
        'last_name_attribute' => 'urn:oid:2.5.4.4', // 'surname'
        /**
         * Default WordPress role to grant when provisioning new users.
         *
         * @param string
         */
        'default_role'           => get_option( 'default_role' ),
    );
    $value = isset( $defaults[ $option_name ] ) ? $defaults[ $option_name ] : $value;
    return $value;
}
add_filter( 'wp_saml_auth_option', 'wpsax_filter_option', 10, 2 );

function custom_query_vars_filter($vars) {
    $vars[] .= 'saml_sso';
    return $vars;
}
add_filter( 'query_vars', 'custom_query_vars_filter' );

add_action( 'login_form', function() {
    if (get_query_var('saml_sso')) {
        ?><input type="text" name="saml_sso" value="false" /><?php
    }
});


/*
 * Return an associative array of groups, indexed by role
 */
function site_role_groups() {
    $domain = parse_url(site_url(), PHP_URL_HOST);

    /**
     * reduce the hostname down to just the first section, after removing prefixes like "dev." or "test."
     */
    $site = preg_replace('/^((dev|test)\.)/', '', $domain);
    $site = preg_replace('/\..*/', '', $site);

    $site_stem = WP_SAML_AUTH_UW_GROUP_STEM.'_'.$site;

    $role_map = array();
    foreach (wp_roles()->role_names as $role => $name) {
        $role_map[$role] = $site_stem.'_'.$role;
    }
    return $role_map;
}

/*
 * Return the super admin group
 */
function super_admin_group() {
    return WP_SAML_AUTH_UW_GROUP_STEM.'_admin';
}

/*
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

add_action( 'admin_menu', function() {
    add_options_page(
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
                    <tr><th scope="row">Assertion Consumer Service URL</th>
                        <td><input readonly="readonly" type="text" class="regular-text" value="<?= $config['sp']['assertionConsumerService']['url'] ?>" /></td></tr>
                </table>
                <h2>Role Mapping</h2>
                <p>Roles will be granted based on membership in these UW Groups:</p>
                <table class="form-table" role="presentation">
                    <tr><th scope="row">Super Admin</th>
                    <td><input readonly="readonly" type="text" class="regular-text" value="<?= super_admin_group() ?>" /></td></tr>
<?php foreach (wp_roles()->get_names() as $role => $name): ?>
                    <tr><th scope="row"><?= $name ?></th>
                    <td><input readonly="readonly" type="text" class="regular-text" value="<?= $groups[$role] ?>" /></td></tr>
<?php endforeach; ?>
                </table>
            </div>
            <?php
        }
    );
});
