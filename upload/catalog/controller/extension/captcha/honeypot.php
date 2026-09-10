<?php
class ControllerExtensionCaptchaHoneypot extends Controller {
    private $yandexError = '';

    public function index($error = array()) {
        if (!$this->config->get('captcha_honeypot_status')) {
            return '';
        }

        $token = $this->makeToken();
        $now = microtime(true);
        $ttl = max(60, min(7200, (int)$this->config->get('captcha_honeypot_token_ttl')));

        if (!isset($this->session->data['honeypot_tokens']) || !is_array($this->session->data['honeypot_tokens'])) {
            $this->session->data['honeypot_tokens'] = array();
        }

        foreach ($this->session->data['honeypot_tokens'] as $key => $entry) {
            $expires = is_array($entry) && isset($entry['expires']) ? (float)$entry['expires'] : 0;
            if ($expires && $expires < $now) {
                unset($this->session->data['honeypot_tokens'][$key]);
            }
        }

        if (count($this->session->data['honeypot_tokens']) > 20) {
            $this->session->data['honeypot_tokens'] = array_slice($this->session->data['honeypot_tokens'], -10, null, true);
        }

        $this->session->data['honeypot_tokens'][$token] = array(
            'started' => $now,
            'expires' => $now + $ttl,
            'ua_hash' => $this->userAgentHash()
        );

        $data['hp_token'] = $token;
        $data['field_name'] = 'hp_' . substr(hash('sha256', $token . ':a'), 0, 12);
        $data['field_name_2'] = 'hp_' . substr(hash('sha256', $token . ':b'), 0, 12);
        $data['js_name'] = '_hp_js_' . substr(hash('sha256', $token . ':js'), 0, 8);
        $data['js_value'] = substr(hash('sha256', $token . ':ok'), 0, 20);

        $data['yandex_enabled'] = false;
        $data['yandex_site_key'] = '';
        $data['yandex_error'] = '';

        if ($this->shouldRenderYandexRegistration()) {
            $keys = $this->getYandexKeys();
            $data['yandex_enabled'] = !empty($keys['site_key']);
            $data['yandex_site_key'] = $keys['site_key'];
            if (isset($error['captcha'])) {
                $data['yandex_error'] = $error['captcha'];
            }
        }

        return $this->load->view('extension/captcha/honeypot', $data);
    }

    public function validate() {
        if (!$this->config->get('captcha_honeypot_status')) {
            return;
        }

        $route = isset($this->request->get['route']) ? (string)$this->request->get['route'] : '';
        $ip = $this->getClientIp();
        $rate_scope = $this->getRateScope($route);

        $rate_blocked = $this->isRateBlocked($ip, $rate_scope);
        $yandex_required = $this->shouldVerifyYandexRegistration();
        $captcha_recovery = $this->isRegistrationSubmission($route)
            && $yandex_required;

        if ($rate_blocked && !$captcha_recovery) {
            $this->logDetection('rate_limit', '', 0);
            return $this->getErrorMessage();
        }

        if ($rate_blocked) {
            $this->logDetection('rate_limit_challenge', '', 0);
        }

        $token = isset($this->request->post['_hp_token']) ? (string)$this->request->post['_hp_token'] : '';
        if ($token === '' || !isset($this->session->data['honeypot_tokens']) || !is_array($this->session->data['honeypot_tokens'])) {
            return $this->reject('missing_session', '', 0, $ip, $rate_scope);
        }

        if (!isset($this->session->data['honeypot_tokens'][$token]) || !is_array($this->session->data['honeypot_tokens'][$token])) {
            return $this->reject('invalid_token', '', 0, $ip, $rate_scope);
        }

        $entry = $this->session->data['honeypot_tokens'][$token];
        $started = isset($entry['started']) ? (float)$entry['started'] : 0;
        $expires = isset($entry['expires']) ? (float)$entry['expires'] : 0;
        $elapsed = $started > 0 ? max(0, microtime(true) - $started) : 0;

        if ($expires > 0 && microtime(true) > $expires) {
            return $this->reject('expired_token', '', $elapsed, $ip, $rate_scope);
        }

        if (!empty($entry['ua_hash']) && !hash_equals((string)$entry['ua_hash'], $this->userAgentHash())) {
            return $this->reject('client_mismatch', '', $elapsed, $ip, $rate_scope);
        }

        $field_name = 'hp_' . substr(hash('sha256', $token . ':a'), 0, 12);
        $field_name_2 = 'hp_' . substr(hash('sha256', $token . ':b'), 0, 12);

        if (!array_key_exists($field_name, $this->request->post) || !array_key_exists($field_name_2, $this->request->post)) {
            return $this->reject('missing_trap', '', $elapsed, $ip, $rate_scope);
        }

        $trap_value = trim((string)$this->request->post[$field_name]);
        $trap_value_2 = trim((string)$this->request->post[$field_name_2]);

        if ($trap_value !== '' || $trap_value_2 !== '') {
            return $this->reject('honeypot', trim($trap_value . ' ' . $trap_value_2), $elapsed, $ip, $rate_scope);
        }

        if ($this->isRegistrationSubmission($route) && $this->config->get('captcha_honeypot_phone_check_status')) {
            if (!$this->validateRegistrationPhone()) {
                $this->reject('invalid_phone', $this->getRegistrationPhone(), $elapsed, $ip, $rate_scope, false);
                $this->load->language('extension/captcha/honeypot');
                return $this->language->get('error_phone');
            }
        }

        if ($yandex_required) {
            if (!$this->verifyYandexSmartCaptcha()) {
                return $this->reject('yandex_failed', $this->yandexError, $elapsed, $ip, $rate_scope);
            }
        } else {
            if ($this->config->get('captcha_honeypot_js_check_status')) {
                $js_name = '_hp_js_' . substr(hash('sha256', $token . ':js'), 0, 8);
                $expected = substr(hash('sha256', $token . ':ok'), 0, 20);
                $actual = isset($this->request->post[$js_name]) ? (string)$this->request->post[$js_name] : '';

                if ($actual === '' || !hash_equals($expected, $actual)) {
                    return $this->reject('js_check', '', $elapsed, $ip, $rate_scope);
                }
            }

            if ($this->config->get('captcha_honeypot_time_check_status')) {
                $min_seconds = max(0, (int)$this->config->get('captcha_honeypot_min_seconds'));
                if ($min_seconds > 0 && $elapsed < $min_seconds) {
                    return $this->reject('too_fast', '', $elapsed, $ip, $rate_scope);
                }
            }
        }

        $this->clearRateLimit($ip, $rate_scope);

        if (!isset($this->session->data['honeypot_passed_tokens']) || !is_array($this->session->data['honeypot_passed_tokens'])) {
            $this->session->data['honeypot_passed_tokens'] = array();
        }

        $this->session->data['honeypot_passed_tokens'][$token] = array(
            'elapsed' => $elapsed,
            'route' => $route
        );
    }

    public function guardCustomerCreation($customer_data = array()) {
        if (!$this->config->get('captcha_honeypot_status')) {
            return true;
        }

        $route = isset($this->request->get['route']) ? (string)$this->request->get['route'] : '';

        $customer_phone = '';
        if (is_array($customer_data) && isset($customer_data['telephone']) && is_scalar($customer_data['telephone'])) {
            $customer_phone = trim((string)$customer_data['telephone']);
        } else {
            $customer_phone = $this->getRegistrationPhone();
        }

        if ($customer_phone !== ''
            && $this->config->get('captcha_honeypot_phone_check_status')
            && !$this->isValidRegistrationPhone($customer_phone)) {
            $this->logDetection('model_invalid_phone', $customer_phone, 0);
            return false;
        }

        $token = isset($this->request->post['_hp_token']) ? (string)$this->request->post['_hp_token'] : '';

        if ($token !== ''
            && isset($this->session->data['honeypot_passed_tokens'][$token])
            && is_array($this->session->data['honeypot_passed_tokens'][$token])) {
            $passed_route = isset($this->session->data['honeypot_passed_tokens'][$token]['route'])
                ? (string)$this->session->data['honeypot_passed_tokens'][$token]['route']
                : '';

            if ($passed_route === $route) {
                return true;
            }
        }

        $allowed_prefixes = array(
            'checkout/uni_checkout',
            'checkout/simplecheckout',
            'extension/module/pp_login',
            'extension/module/amazon_login',
            'extension/module/amazon_pay'
        );

        foreach ($allowed_prefixes as $prefix) {
            if ($route === $prefix || strpos($route, $prefix . '/') === 0) {
                $this->logDetection('customer_create_unverified', '', 0);
                return true;
            }
        }

        if ($route === '') {
            $this->logDetection('customer_create_unverified', 'empty_route', 0);
            return true;
        }

        $this->logDetection('unprotected_create', '', 0);
        return false;
    }

    public function consume() {
        $token = isset($this->request->post['_hp_token']) ? (string)$this->request->post['_hp_token'] : '';

        if ($token === '') {
            return;
        }

        if (isset($this->session->data['honeypot_passed_tokens'][$token])) {
            $passed = $this->session->data['honeypot_passed_tokens'][$token];
            $route = isset($passed['route']) ? (string)$passed['route'] : '';
            $elapsed = isset($passed['elapsed']) ? (float)$passed['elapsed'] : 0;

            if ($this->isRegistrationSubmission($route) && $this->config->get('captcha_honeypot_log_success_status')) {
                $this->logDetection('registration_passed', '', $elapsed);
            }

            unset($this->session->data['honeypot_passed_tokens'][$token]);
        }

        if (isset($this->session->data['honeypot_tokens'][$token])) {
            unset($this->session->data['honeypot_tokens'][$token]);
        }
    }

    private function shouldRenderYandexRegistration() {
        $route = isset($this->request->get['route']) ? (string)$this->request->get['route'] : '';
        return $this->isRegistrationFormRequest($route)
            && $this->config->get('captcha_honeypot_yandex_status')
            && $this->config->get('captcha_honeypot_yandex_register_status')
            && !$this->isPrimaryYandexRegistration()
            && $this->isYandexReady();
    }

    private function shouldVerifyYandexRegistration() {
        $route = isset($this->request->get['route']) ? (string)$this->request->get['route'] : '';
        return $this->isRegistrationSubmission($route)
            && $this->config->get('captcha_honeypot_yandex_status')
            && $this->config->get('captcha_honeypot_yandex_register_status')
            && !$this->isPrimaryYandexRegistration()
            && $this->isYandexReady();
    }

    private function isRegistrationFormRequest($route) {
        if (in_array($route, array(
            'account/register',
            'account/simpleregister',
            'extension/module/uni_login_register/page'
        ), true)) {
            return true;
        }

        return $route === 'extension/module/uni_login_register/modal'
            && isset($this->request->post['type'])
            && $this->request->post['type'] === 'register';
    }

    private function isRegistrationSubmission($route) {
        return in_array($route, array(
            'account/register',
            'account/simpleregister',
            'extension/module/uni_login_register/register'
        ), true);
    }

    private function isPrimaryYandexRegistration() {
        if ($this->config->get('config_captcha') !== 'yandex' || !$this->config->get('captcha_yandex_status')) {
            return false;
        }

        $route = isset($this->request->get['route']) ? (string)$this->request->get['route'] : '';
        if (strpos($route, 'extension/module/uni_login_register/') === 0) {
            return true;
        }

        $pages = (array)$this->config->get('config_captcha_page');
        return in_array('register', $pages, true);
    }

    private function getYandexKeys() {
        $source = (string)$this->config->get('captcha_honeypot_yandex_source');
        if ($source === 'standard') {
            return array(
                'site_key' => trim((string)$this->config->get('captcha_yandex_key')),
                'secret' => trim((string)$this->config->get('captcha_yandex_secret'))
            );
        }

        return array(
            'site_key' => trim((string)$this->config->get('captcha_honeypot_yandex_key')),
            'secret' => trim((string)$this->config->get('captcha_honeypot_yandex_secret'))
        );
    }

    private function isYandexReady() {
        $keys = $this->getYandexKeys();
        return $keys['site_key'] !== '' && $keys['secret'] !== '';
    }

    private function verifyYandexSmartCaptcha() {
        $this->yandexError = '';

        if (empty($this->request->post['smart-token'])) {
            $this->yandexError = 'missing_smart_token';
            return false;
        }

        $keys = $this->getYandexKeys();
        if ($keys['secret'] === '') {
            $this->yandexError = 'missing_secret';
            return false;
        }

        $args = http_build_query(array(
            'secret' => $keys['secret'],
            'token' => (string)$this->request->post['smart-token'],
            'ip' => $this->getClientIp()
        ));

        $ch = curl_init('https://smartcaptcha.cloud.yandex.ru/validate');
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $args);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        $response = curl_exec($ch);
        $curl_errno = (int)curl_errno($ch);
        $httpcode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($curl_errno) {
            $this->yandexError = 'curl_' . $curl_errno;
            return false;
        }

        if ($httpcode !== 200) {
            $this->yandexError = 'http_' . $httpcode;
            return false;
        }

        if (!$response) {
            $this->yandexError = 'empty_response';
            return false;
        }

        $result = json_decode($response, true);
        if (!is_array($result)) {
            $this->yandexError = 'invalid_json';
            return false;
        }

        if (!isset($result['status']) || $result['status'] !== 'ok') {
            $this->yandexError = 'status_failed';

            if (!empty($result['message']) && is_scalar($result['message'])) {
                $message = preg_replace('/[^a-zA-Z0-9_.: -]/', '', (string)$result['message']);
                $message = substr(trim($message), 0, 160);

                if ($message !== '') {
                    $this->yandexError .= ': ' . $message;
                }
            }

            return false;
        }

        return true;
    }

    private function getRegistrationPhone() {
        if (isset($this->request->post['telephone']) && is_scalar($this->request->post['telephone'])) {
            return trim((string)$this->request->post['telephone']);
        }

        if (isset($this->request->post['register']['telephone']) && is_scalar($this->request->post['register']['telephone'])) {
            return trim((string)$this->request->post['register']['telephone']);
        }

        return '';
    }

    private function validateRegistrationPhone() {
        return $this->isValidRegistrationPhone($this->getRegistrationPhone());
    }

    private function isValidRegistrationPhone($phone) {
        $phone = trim((string)$phone);
        if ($phone === '') {
            return false;
        }

        if (!preg_match('/^[0-9+()\-\s]+$/u', $phone)) {
            return false;
        }

        $digits = preg_replace('/\D+/', '', $phone);
        $length = strlen($digits);
        if ($length < 10 || $length > 11) {
            return false;
        }

        if ($this->config->get('captcha_honeypot_phone_ru_status')) {
            if ($length === 11 && $digits[0] !== '7' && $digits[0] !== '8') {
                return false;
            }
            if ($length === 10 && $digits[0] !== '9') {
                return false;
            }
        }

        return true;
    }

    private function getClientIp() {
        $ip = '';
        if (!empty($this->request->server['HTTP_CF_CONNECTING_IP'])) {
            $ip = (string)$this->request->server['HTTP_CF_CONNECTING_IP'];
        } elseif (!empty($this->request->server['HTTP_X_FORWARDED_FOR'])) {
            $parts = explode(',', (string)$this->request->server['HTTP_X_FORWARDED_FOR']);
            $ip = trim($parts[0]);
        } elseif (!empty($this->request->server['REMOTE_ADDR'])) {
            $ip = (string)$this->request->server['REMOTE_ADDR'];
        }
        return $this->limit($ip, 45);
    }

    private function getErrorMessage() {
        $this->load->language('extension/captcha/honeypot');
        return $this->language->get('error_captcha');
    }

    private function getRateScope($route) {
        return $this->isRegistrationSubmission($route) ? 'registration' : $route;
    }

    private function reject($reason, $trap_value, $elapsed, $ip, $scope, $count_rate = true) {
        $this->logDetection($reason, $trap_value, $elapsed);

        if ($count_rate) {
            $this->recordRateFailure($ip, $scope);
        }

        return $this->getErrorMessage();
    }

    private function isRateBlocked($ip, $scope) {
        if (!$this->config->get('captcha_honeypot_rate_limit_status') || $ip === '') {
            return false;
        }

        $this->ensureRateTable();
        $key = hash('sha256', $ip . '|' . $scope);
        $query = $this->db->query("SELECT * FROM `" . DB_PREFIX . "honeypot_rate` WHERE `rate_key` = '" . $this->db->escape($key) . "' LIMIT 1");

        if (!$query->num_rows) {
            return false;
        }

        $now = time();
        $blocked_until = !empty($query->row['blocked_until']) ? strtotime($query->row['blocked_until']) : 0;
        return $blocked_until && $blocked_until > $now;
    }

    private function recordRateFailure($ip, $scope) {
        if (!$this->config->get('captcha_honeypot_rate_limit_status') || $ip === '') {
            return;
        }

        $limit = max(1, min(100, (int)$this->config->get('captcha_honeypot_rate_limit')));
        $window = max(60, min(86400, (int)$this->config->get('captcha_honeypot_rate_window')));
        $block = max(60, min(86400, (int)$this->config->get('captcha_honeypot_block_seconds')));
        $this->ensureRateTable();

        $key = hash('sha256', $ip . '|' . $scope);
        $query = $this->db->query("SELECT * FROM `" . DB_PREFIX . "honeypot_rate` WHERE `rate_key` = '" . $this->db->escape($key) . "' LIMIT 1");
        $now = time();

        if (!$query->num_rows) {
            $this->db->query("INSERT INTO `" . DB_PREFIX . "honeypot_rate` SET `rate_key` = '" . $this->db->escape($key) . "', ip = '" . $this->db->escape($this->limit($ip, 45)) . "', route = '" . $this->db->escape($this->limit($scope, 255)) . "', attempts = 1, window_started = FROM_UNIXTIME('" . $now . "'), last_seen = NOW(), blocked_until = NULL");
            return;
        }

        $row = $query->row;
        $window_started = !empty($row['window_started']) ? strtotime($row['window_started']) : 0;

        if (!$window_started || ($now - $window_started) >= $window) {
            $this->db->query("UPDATE `" . DB_PREFIX . "honeypot_rate` SET attempts = 1, window_started = NOW(), last_seen = NOW(), blocked_until = NULL WHERE `rate_key` = '" . $this->db->escape($key) . "'");
            return;
        }

        $attempts = (int)$row['attempts'] + 1;
        $blocked_sql = $attempts >= $limit ? ", blocked_until = DATE_ADD(NOW(), INTERVAL " . $block . " SECOND)" : "";
        $this->db->query("UPDATE `" . DB_PREFIX . "honeypot_rate` SET attempts = '" . $attempts . "', last_seen = NOW()" . $blocked_sql . " WHERE `rate_key` = '" . $this->db->escape($key) . "'");
    }

    private function clearRateLimit($ip, $scope) {
        if (!$this->config->get('captcha_honeypot_rate_limit_status') || $ip === '') {
            return;
        }

        $this->ensureRateTable();
        $key = hash('sha256', $ip . '|' . $scope);
        $this->db->query("DELETE FROM `" . DB_PREFIX . "honeypot_rate` WHERE `rate_key` = '" . $this->db->escape($key) . "'");
    }

    private function makeToken() {
        if (function_exists('random_bytes')) {
            try {
                return bin2hex(random_bytes(16));
            } catch (Exception $e) {
            }
        }
        return sha1(uniqid((string)mt_rand(), true) . microtime(true));
    }

    private function userAgentHash() {
        $ua = isset($this->request->server['HTTP_USER_AGENT']) ? (string)$this->request->server['HTTP_USER_AGENT'] : '';
        return hash('sha256', $ua);
    }

    private function logDetection($reason, $trap_value, $elapsed) {
        if (!$this->config->get('captcha_honeypot_log_status')) {
            return;
        }

        $email = '';
        foreach (array('email', 'customer_email', 'mail') as $key) {
            if (!empty($this->request->post[$key]) && is_scalar($this->request->post[$key])) {
                $email = (string)$this->request->post[$key];
                break;
            }
        }

        if ($email === '' && !empty($this->request->post['register']['email']) && is_scalar($this->request->post['register']['email'])) {
            $email = (string)$this->request->post['register']['email'];
        }

        $name = '';
        foreach (array('name', 'firstname', 'author', 'customer_name') as $key) {
            if (!empty($this->request->post[$key]) && is_scalar($this->request->post[$key])) {
                $name = (string)$this->request->post[$key];
                break;
            }
        }

        $route = isset($this->request->get['route']) ? (string)$this->request->get['route'] : '';
        $ip = $this->getClientIp();
        $user_agent = isset($this->request->server['HTTP_USER_AGENT']) ? (string)$this->request->server['HTTP_USER_AGENT'] : '';
        $request_uri = isset($this->request->server['REQUEST_URI']) ? (string)$this->request->server['REQUEST_URI'] : '';

        $this->ensureLogTable();
        $this->db->query("INSERT INTO `" . DB_PREFIX . "honeypot_log` SET store_id = '" . (int)$this->config->get('config_store_id') . "', route = '" . $this->db->escape($this->limit($route, 255)) . "', email = '" . $this->db->escape($this->limit($email, 255)) . "', name = '" . $this->db->escape($this->limit($name, 255)) . "', ip = '" . $this->db->escape($this->limit($ip, 45)) . "', user_agent = '" . $this->db->escape($this->limit($user_agent, 512)) . "', reason = '" . $this->db->escape($this->limit($reason, 32)) . "', trap_value = '" . $this->db->escape($this->limit($trap_value, 255)) . "', elapsed = '" . (float)$elapsed . "', request_uri = '" . $this->db->escape($this->limit($request_uri, 512)) . "', date_added = NOW()");
    }

    private function ensureLogTable() {
        $this->db->query("CREATE TABLE IF NOT EXISTS `" . DB_PREFIX . "honeypot_log` (`honeypot_log_id` INT(11) NOT NULL AUTO_INCREMENT, `store_id` INT(11) NOT NULL DEFAULT '0', `route` VARCHAR(255) NOT NULL DEFAULT '', `email` VARCHAR(255) NOT NULL DEFAULT '', `name` VARCHAR(255) NOT NULL DEFAULT '', `ip` VARCHAR(45) NOT NULL DEFAULT '', `user_agent` VARCHAR(512) NOT NULL DEFAULT '', `reason` VARCHAR(32) NOT NULL DEFAULT '', `trap_value` VARCHAR(255) NOT NULL DEFAULT '', `elapsed` DECIMAL(10,3) NOT NULL DEFAULT '0.000', `request_uri` VARCHAR(512) NOT NULL DEFAULT '', `date_added` DATETIME NOT NULL, PRIMARY KEY (`honeypot_log_id`), KEY `email` (`email`), KEY `ip` (`ip`), KEY `reason` (`reason`), KEY `date_added` (`date_added`)) ENGINE=InnoDB DEFAULT CHARSET=utf8");
    }

    private function ensureRateTable() {
        $this->db->query("CREATE TABLE IF NOT EXISTS `" . DB_PREFIX . "honeypot_rate` (`rate_key` CHAR(64) NOT NULL, `ip` VARCHAR(45) NOT NULL DEFAULT '', `route` VARCHAR(255) NOT NULL DEFAULT '', `attempts` INT(11) NOT NULL DEFAULT '0', `window_started` DATETIME NOT NULL, `last_seen` DATETIME NOT NULL, `blocked_until` DATETIME NULL, PRIMARY KEY (`rate_key`), KEY `last_seen` (`last_seen`), KEY `blocked_until` (`blocked_until`)) ENGINE=InnoDB DEFAULT CHARSET=utf8");
        if (mt_rand(1, 100) === 1) {
            $this->db->query("DELETE FROM `" . DB_PREFIX . "honeypot_rate` WHERE last_seen < DATE_SUB(NOW(), INTERVAL 2 DAY)");
        }
    }

    private function limit($value, $length) {
        $value = (string)$value;
        if (function_exists('utf8_substr')) {
            return utf8_substr($value, 0, $length);
        }
        return substr($value, 0, $length);
    }
}
