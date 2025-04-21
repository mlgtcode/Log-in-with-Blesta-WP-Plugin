<?php
/*
Plugin Name: Blesta Login Integration
Plugin URI: https://mlgt.info/
Description: Allow users to log in to WordPress using their Blesta username and password.
Version: 1.0
Author: MLGT
Author URI: https://mlgt.info/
*/

class BlestaResponse {
    private string $raw;
    private int $response_code;

    public function __construct(string $response, int $response_code) {
        $this->raw = $response;
        $this->response_code = $response_code;
    }

    public function response(): mixed {
        $response = $this->formatResponse();
        return $response->response ?? null;
    }

    public function responseCode(): int {
        return $this->response_code;
    }

    public function raw(): string {
        return $this->raw;
    }

    public function errors(): stdClass|false {
        if ($this->response_code !== 200) {
            $response = $this->formatResponse();

            if (isset($response->errors)) {
                return $response->errors;
            }

            $error = new stdClass();
            $error->error = $response;
            return $error;
        }

        return false;
    }

    private function formatResponse(): ?stdClass {
        return json_decode($this->raw);
    }
}

class BlestaApi {
    private string $url;
    private string $user;
    private string $key;
    private bool $ssl_verify;
    private bool $debug;
    private ?array $last_request = null;
    private const FORMAT = "json";

    public function __construct(array $config) {
        $this->url = $config['url'] ?? throw new InvalidArgumentException("API URL is required.");
        $this->user = $config['user'] ?? throw new InvalidArgumentException("API user is required.");
        $this->key = $config['key'] ?? throw new InvalidArgumentException("API key is required.");
        $this->ssl_verify = $config['ssl_verify'] ?? true;
        $this->debug = $config['debug'] ?? false;
    }

    public function get(string $model, string $method, array $args = []): BlestaResponse {
        return $this->submit($model, $method, $args, "GET");
    }

    public function post(string $model, string $method, array $args = []): BlestaResponse {
        return $this->submit($model, $method, $args, "POST");
    }

    private function submit(string $model, string $method, array $args = [], string $action = "POST"): BlestaResponse {
        $url = $this->url . $model . "/" . $method . "." . self::FORMAT;

        $this->last_request = [
            'url' => $url,
            'args' => $args
        ];

        if ($action === "GET") {
            $url .= "?" . http_build_query($args);
            $args = null;
        }

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $action);
        curl_setopt($ch, CURLOPT_URL, $url);

        if ($args) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($args));
        }

        curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
        curl_setopt($ch, CURLOPT_USERPWD, "{$this->user}:{$this->key}");

        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $this->ssl_verify);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, $this->ssl_verify ? 2 : 0);

        $response = curl_exec($ch);
        $response_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        if ($response === false) {
            $error = curl_error($ch);
            curl_close($ch);
            throw new RuntimeException("cURL error: $error");
        }

        curl_close($ch);

        if ($this->debug) {
            echo "Debug Info:\n";
            echo "URL: $url\n";
            echo "Action: $action\n";
            echo "Response Code: $response_code\n";
            echo "Response: $response\n";
        }

        return new BlestaResponse($response, $response_code);
    }

    public function lastRequest(): ?array {
        return $this->last_request;
    }
}

class BlestaApiHandler {
    private $api;

    public function __construct() {
        $this->api = new BlestaApi([
            'url' => get_option('blesta_api_url', ''),
            'user' => get_option('blesta_api_user', ''),
            'key' => get_option('blesta_api_key', ''),
            'ssl_verify' => get_option('blesta_api_ssl_verify', true),
            'debug' => get_option('blesta_api_debug', false)
        ]);
    }

    public function authenticateUser($username, $password) {
        try {
            $data = [
                'username' => $username,
                'vars' => [
                    'username' => $username,
                    'password' => $password
                ],
                'type' => 'any'
            ];

            $response = $this->api->post('users', 'auth', $data);

            if ($response->responseCode() === 200 && $response->response()) {
                return $response->response();
            } else {
                return new WP_Error('invalid_credentials', __('Invalid Blesta credentials.', 'blesta-login-integration'));
            }
        } catch (Exception $e) {
            return new WP_Error('blesta_api_error', __('Blesta API error: ' . $e->getMessage(), 'blesta-login-integration'));
        }
    }
}

function encrypt_blesta_integration_key($key) {
    $encryption_key = wp_salt('auth');
    return base64_encode(openssl_encrypt($key, 'aes-256-cbc', $encryption_key, 0, substr($encryption_key, 0, 16)));
}

function decrypt_blesta_integration_key($encrypted_key) {
    $encryption_key = wp_salt('auth');
    return openssl_decrypt(base64_decode($encrypted_key), 'aes-256-cbc', $encryption_key, 0, substr($encryption_key, 0, 16));
}

add_action('admin_menu', 'blesta_api_config_menu');

function blesta_api_config_menu() {
    add_options_page(
        __('Blesta API Configuration', 'blesta-login-integration'),
        __('Blesta API Configuration', 'blesta-login-integration'),
        'manage_options',
        'blesta-api-config',
        'blesta_api_config_page'
    );
}

add_action('admin_init', function () {
    register_setting('blesta_api_config', 'blesta_api_url', [
        'type' => 'string',
        'sanitize_callback' => 'sanitize_text_field',
        'default' => '',
    ]);
    register_setting('blesta_api_config', 'blesta_api_user', [
        'type' => 'string',
        'sanitize_callback' => 'sanitize_text_field',
        'default' => '',
    ]);
    register_setting('blesta_api_config', 'blesta_api_key', [
        'type' => 'string',
        'sanitize_callback' => 'sanitize_text_field',
        'default' => '',
    ]);
    register_setting('blesta_api_config', 'blesta_api_ssl_verify', [
        'type' => 'boolean',
        'sanitize_callback' => 'rest_sanitize_boolean',
        'default' => true,
    ]);
    register_setting('blesta_api_config', 'blesta_api_debug', [
        'type' => 'boolean',
        'sanitize_callback' => 'rest_sanitize_boolean',
        'default' => false,
    ]);
    register_setting('blesta_api_config', 'blesta_enable_user_creation', [
        'type' => 'boolean',
        'sanitize_callback' => 'rest_sanitize_boolean',
        'default' => true,
    ]);
    register_setting('blesta_api_config', 'blesta_turnstile_site_key', [
        'type' => 'string',
        'sanitize_callback' => 'sanitize_text_field',
        'default' => '',
    ]);
    register_setting('blesta_api_config', 'blesta_turnstile_secret_key', [
        'type' => 'string',
        'sanitize_callback' => 'sanitize_text_field',
        'default' => '',
    ]);
    register_setting('blesta_api_config', 'blesta_enable_turnstile', [
        'type' => 'boolean',
        'sanitize_callback' => 'rest_sanitize_boolean',
        'default' => false,
    ]);
});

function blesta_api_config_page() {
    if (!current_user_can('manage_options')) {
        wp_die(__('You do not have sufficient permissions to access this page.', 'blesta-login-integration'));
    }

    if (isset($_POST['blesta_api_url']) && isset($_POST['blesta_api_user']) && isset($_POST['blesta_api_key'])) {
        update_option('blesta_api_url', sanitize_text_field($_POST['blesta_api_url']));
        update_option('blesta_api_user', sanitize_text_field($_POST['blesta_api_user']));
        $encrypted_key = encrypt_blesta_integration_key(sanitize_text_field($_POST['blesta_api_key']));
        update_option('blesta_api_key', $encrypted_key);
        update_option('blesta_api_ssl_verify', isset($_POST['blesta_api_ssl_verify']));
        update_option('blesta_api_debug', isset($_POST['blesta_api_debug']));
        update_option('blesta_enable_user_creation', isset($_POST['blesta_enable_user_creation']));
    }

    if (isset($_POST['blesta_turnstile_site_key']) && isset($_POST['blesta_turnstile_secret_key'])) {
        update_option('blesta_turnstile_site_key', sanitize_text_field($_POST['blesta_turnstile_site_key']));
        update_option('blesta_turnstile_secret_key', sanitize_text_field($_POST['blesta_turnstile_secret_key']));
        update_option('blesta_enable_turnstile', isset($_POST['blesta_enable_turnstile']));
        echo '<div class="updated"><p>' . __('Settings saved.', 'blesta-login-integration') . '</p></div>';
    }

    $blesta_api_url = get_option('blesta_api_url', '');
    $blesta_api_user = get_option('blesta_api_user', '');
    $encrypted_key = get_option('blesta_api_key', '');
    $blesta_api_key = $encrypted_key ? decrypt_blesta_integration_key($encrypted_key) : '';
    $blesta_api_ssl_verify = get_option('blesta_api_ssl_verify', true);
    $blesta_api_debug = get_option('blesta_api_debug', false);
    $blesta_enable_user_creation = get_option('blesta_enable_user_creation', true);
    $blesta_turnstile_site_key = get_option('blesta_turnstile_site_key', '');
    $blesta_turnstile_secret_key = get_option('blesta_turnstile_secret_key', '');
    $blesta_enable_turnstile = get_option('blesta_enable_turnstile', false);

    echo '<div class="wrap">';
    echo '<h1>' . __('General Settings', 'blesta-login-integration') . '</h1>';
    echo '<p>' . __('Configure the general settings for the Blesta API integration, including API credentials and user creation options.', 'blesta-login-integration') . '</p>';
    echo '<form method="post">';
    echo '<table class="form-table">';
    echo '<tr><th scope="row"><label for="blesta_api_url">' . __('Blesta API URL', 'blesta-login-integration') . '</label></th>';
    echo '<td><input name="blesta_api_url" type="text" id="blesta_api_url" value="' . esc_attr($blesta_api_url) . '" class="regular-text">';
    echo '<p class="description">' . __('Enter the base URL of your Blesta API endpoint (e.g., https://yourdomain.com/api/).', 'blesta-login-integration') . '</p></td></tr>';
    echo '<tr><th scope="row"><label for="blesta_api_user">' . __('Blesta API User', 'blesta-login-integration') . '</label></th>';
    echo '<td><input name="blesta_api_user" type="text" id="blesta_api_user" value="' . esc_attr($blesta_api_user) . '" class="regular-text">';
    echo '<p class="description">' . __('Provide the username for accessing the Blesta API.', 'blesta-login-integration') . '</p></td></tr>';
    echo '<tr><th scope="row"><label for="blesta_api_key">' . __('Blesta API Key', 'blesta-login-integration') . '</label></th>';
    echo '<td><input name="blesta_api_key" type="password" id="blesta_api_key" value="' . esc_attr($blesta_api_key) . '" class="regular-text">';
    echo '<p class="description">' . __('Enter the API key associated with the Blesta API user. This key will be encrypted for security.', 'blesta-login-integration') . '</p></td></tr>';
    echo '<tr><th scope="row"><label for="blesta_api_ssl_verify">' . __('SSL Verification', 'blesta-login-integration') . '</label></th>';
    echo '<td><input name="blesta_api_ssl_verify" type="checkbox" id="blesta_api_ssl_verify" ' . checked($blesta_api_ssl_verify, true, false) . '>'; 
    echo '<p class="description">' . __('Enable this option to verify SSL certificates when connecting to the Blesta API.', 'blesta-login-integration') . '</p></td></tr>';
    echo '<tr><th scope="row"><label for="blesta_api_debug">' . __('Debug Mode', 'blesta-login-integration') . '</label></th>';
    echo '<td><input name="blesta_api_debug" type="checkbox" id="blesta_api_debug" ' . checked($blesta_api_debug, true, false) . '>'; 
    echo '<p class="description">' . __('Enable debug mode to log API requests and responses for troubleshooting purposes.', 'blesta-login-integration') . '</p></td></tr>';
    echo '<tr><th scope="row"><label for="blesta_enable_user_creation">' . __('Enable User Creation', 'blesta-login-integration') . '</label></th>';
    echo '<td><input name="blesta_enable_user_creation" type="checkbox" id="blesta_enable_user_creation" ' . checked($blesta_enable_user_creation, true, false) . '>'; 
    echo '<p class="description">' . __('Allow automatic creation of WordPress accounts for users who authenticate successfully via the Blesta API.', 'blesta-login-integration') . '</p></td></tr>';
    echo '</table>';

    echo '<h1>' . __('Captcha Settings', 'blesta-login-integration') . '</h1>';
    echo '<p>' . __('Configure the CAPTCHA settings to enhance security during login attempts.', 'blesta-login-integration') . '</p>';
    echo '<table class="form-table">';
    echo '<tr><th scope="row"><label for="blesta_turnstile_site_key">' . __('Turnstile Site Key', 'blesta-login-integration') . '</label></th>';
    echo '<td><input name="blesta_turnstile_site_key" type="text" id="blesta_turnstile_site_key" value="' . esc_attr($blesta_turnstile_site_key) . '" class="regular-text">';
    echo '<p class="description">' . __('Enter the site key provided by Cloudflare Turnstile for CAPTCHA verification.', 'blesta-login-integration') . '</p></td></tr>';
    echo '<tr><th scope="row"><label for="blesta_turnstile_secret_key">' . __('Turnstile Secret Key', 'blesta-login-integration') . '</label></th>';
    echo '<td><input name="blesta_turnstile_secret_key" type="password" id="blesta_turnstile_secret_key" value="' . esc_attr($blesta_turnstile_secret_key) . '" class="regular-text">';
    echo '<p class="description">' . __('Enter the secret key provided by Cloudflare Turnstile for CAPTCHA verification. This key will be encrypted for security.', 'blesta-login-integration') . '</p></td></tr>';
    echo '<tr><th scope="row"><label for="blesta_enable_turnstile">' . __('Enable Turnstile CAPTCHA', 'blesta-login-integration') . '</label></th>';
    echo '<td><input name="blesta_enable_turnstile" type="checkbox" id="blesta_enable_turnstile" ' . checked($blesta_enable_turnstile, true, false) . '>'; 
    echo '<p class="description">' . __('Enable this option to add CAPTCHA verification to the login form, enhancing security against automated login attempts.', 'blesta-login-integration') . '</p></td></tr>';
    echo '</table>';

    echo '<p class="submit"><input type="submit" class="button-primary" value="' . __('Save Changes', 'blesta-login-integration') . '"></p>';
    echo '</form>';
    echo '</div>';
}

add_action('admin_init', function () {
    if (get_option('blesta_restrict_wp_admin', false) && !current_user_can('administrator') && !wp_doing_ajax()) {
        wp_redirect(home_url());
        exit;
    }
});

add_shortcode('blesta_login_form', 'blesta_login_form_shortcode');

function blesta_login_form_shortcode() {
    $blesta_enable_turnstile = get_option('blesta_enable_turnstile', false);
    $blesta_turnstile_site_key = get_option('blesta_turnstile_site_key', '');
    $hide_h1 = get_option('blesta_hide_login_h1', false);

    if (is_user_logged_in()) {
        ob_start();
        echo '<div class="login blogin">';
        echo '<p>' . __('You are already logged in.', 'blesta-login-integration') . '</p>';
        echo '<a href="' . esc_url(wp_logout_url(home_url())) . '" class="button button-secondary">' . __('Logout', 'blesta-login-integration') . '</a>';
        echo '</div>';
        return ob_get_clean();
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['billing_username'], $_POST['billing_password'])) {
        $username = sanitize_text_field($_POST['billing_username']);
        $password = $_POST['billing_password'];

        if ($blesta_enable_turnstile && isset($_POST['cf-turnstile-response'])) {
            $turnstile_response = sanitize_text_field($_POST['cf-turnstile-response']);
            $turnstile_secret_key = get_option('blesta_turnstile_secret_key', '');

            $response = wp_remote_post('https://challenges.cloudflare.com/turnstile/v0/siteverify', [
                'body' => [
                    'secret' => $turnstile_secret_key,
                    'response' => $turnstile_response,
                    'remoteip' => $_SERVER['REMOTE_ADDR']
                ]
            ]);

            $response_body = wp_remote_retrieve_body($response);
            $result = json_decode($response_body, true);

            if (empty($result['success'])) {
                $error_message = __('CAPTCHA verification failed. Please try again.', 'blesta-login-integration');
                $error_html = '<div class="login blogin" style="text-align: center; margin-bottom: 20px;">';
                $error_html .= '<div class="notice notice-error" style="color: red; font-weight: bold; border: 1px solid red; padding: 10px; border-radius: 5px;">';
                $error_html .= '<p>' . esc_html($error_message) . '</p>';
                $error_html .= '<form method="post" style="margin-top: 10px;">';
                $error_html .= '<button type="submit" class="button button-primary">' . __('Try Again', 'blesta-login-integration') . '</button>';
                $error_html .= '</form>';
                $error_html .= '</div></div>';

                ob_start();
                echo '<div class="login blogin">';
                if (!$hide_h1) {
                    echo '<h1>' . __('Login with Billing Credentials', 'blesta-login-integration') . '</h1>';
                }
                echo '<form method="post" class="blogin">';
                echo '<p><label for="billing_username">' . __('Username', 'blesta-login-integration') . '</label><br>'; 
                echo '<input type="text" name="billing_username" id="billing_username" class="input" required></p>';
                echo '<p><label for="billing_password">' . __('Password', 'blesta-login-integration') . '</label><br>'; 
                echo '<input type="password" name="billing_password" id="billing_password" class="input" required></p>';

                if ($blesta_enable_turnstile && $blesta_turnstile_site_key) {
                    echo '<div class="cf-turnstile" data-sitekey="' . esc_attr($blesta_turnstile_site_key) . '"></div>';
                    echo '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>';
                }

                echo '<p><button type="submit" class="button button-primary button-large">' . __('Login', 'blesta-login-integration') . '</button></p>';
                echo '</form>';
                echo '</div>';

                $error_html .= ob_get_clean();
                return $error_html;
            }
        }

        $blesta_api_handler = new BlestaApiHandler();
        $response = $blesta_api_handler->authenticateUser($username, $password);

        if (is_wp_error($response)) {
            $error_message = __('The username or password you entered is incorrect. Please try again.', 'blesta-login-integration');
            $error_html = '<div class="login blogin" style="text-align: center; margin-bottom: 20px;">';
            $error_html .= '<div class="notice notice-error" style="color: red; font-weight: bold; border: 1px solid red; padding: 10px; border-radius: 5px;">';
            $error_html .= '<p>' . esc_html($error_message) . '</p>';
            $error_html .= '</div></div>';

            ob_start();
            echo '<div class="login blogin">';
            if (!$hide_h1) {
                echo '<h1>' . __('Login with Billing Credentials', 'blesta-login-integration') . '</h1>';
            }
            echo '<form method="post" class="blogin">';
            echo '<p><label for="billing_username">' . __('Username', 'blesta-login-integration') . '</label><br>'; 
            echo '<input type="text" name="billing_username" id="billing_username" class="input" required></p>';
            echo '<p><label for="billing_password">' . __('Password', 'blesta-login-integration') . '</label><br>'; 
            echo '<input type="password" name="billing_password" id="billing_password" class="input" required></p>';

            if ($blesta_enable_turnstile && $blesta_turnstile_site_key) {
                echo '<div class="cf-turnstile" data-sitekey="' . esc_attr($blesta_turnstile_site_key) . '"></div>';
                echo '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>';
            }

            echo '<p><button type="submit" class="button button-primary button-large">' . __('Login', 'blesta-login-integration') . '</button></p>';
            echo '</form>';
            echo '</div>';

            $error_html .= ob_get_clean();
            return $error_html;
        } else {
            $user = get_user_by('login', $username);

            if (!$user && get_option('blesta_enable_user_creation', true)) {
                if (filter_var($username, FILTER_VALIDATE_EMAIL)) {
                    $email = $username;
                } else {
                    if (isset($_POST['new_user_email'])) {
                        $email = sanitize_email($_POST['new_user_email']);

                        if (!is_email($email)) {
                            return '<div class="login blogin" style="text-align: center;"><div class="notice notice-error"><p>' . __('Invalid email address provided.', 'blesta-login-integration') . '</p></div></div>';
                        }
                    } else {
                        ob_start();
                        echo '<div class="login blogin">';
                        echo '<h1>' . __('New User Email Required', 'blesta-login-integration') . '</h1>';
                        echo '<form method="post" class="blogin">';
                        echo '<input type="hidden" name="billing_username" value="' . esc_attr($username) . '">';
                        echo '<input type="hidden" name="billing_password" value="' . esc_attr($password) . '">';
                        echo '<p>' . __('Please provide an email address for the new user:', 'blesta-login-integration') . '</p>';
                        echo '<p><input type="email" name="new_user_email" required class="input"></p>';
                        echo '<p><button type="submit" class="button button-primary button-large">' . __('Submit', 'blesta-login-integration') . '</button></p>';
                        echo '</form>';
                        echo '</div>';
                        return ob_get_clean();
                    }
                }

                $user_id = wp_create_user($username, wp_generate_password(), $email);
                $user = get_user_by('id', $user_id);
            }

            wp_set_auth_cookie($user->ID, true);
            wp_redirect(admin_url());
            exit;
        }
    }

    ob_start();
    echo '<div class="login blogin">';
    echo '<form method="post" class="blogin">';

    echo '<p><label for="billing_username">' . __('Username', 'blesta-login-integration') . '</label><br>'; 
    echo '<input type="text" name="billing_username" id="billing_username" class="input" required></p>';
    echo '<p><label for="billing_password">' . __('Password', 'blesta-login-integration') . '</label><br>'; 
    echo '<input type="password" name="billing_password" id="billing_password" class="input" required></p>';

    if ($blesta_enable_turnstile && $blesta_turnstile_site_key) {
        echo '<div class="cf-turnstile" data-sitekey="' . esc_attr($blesta_turnstile_site_key) . '"></div>';
        echo '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>';
    }

    echo '<p><button type="submit" class="button button-primary button-large">' . __('Login', 'blesta-login-integration') . '</button></p>';
    echo '</form>';
    echo '</div>';
    return ob_get_clean();
}

add_action('plugins_loaded', function () {
    load_plugin_textdomain('blesta-login-integration', false, dirname(plugin_basename(__FILE__)) . '/languages');
});

function blesta_login_integration_uninstall() {
    delete_option('blesta_api_key');
}

register_uninstall_hook(__FILE__, 'blesta_login_integration_uninstall');
