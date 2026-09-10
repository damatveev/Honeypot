<?php
class ControllerExtensionCaptchaHoneypot extends Controller {
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

        $data['token'] = $token;
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
        $rate = $this->registerAttempt($ip, $route);

        if ($rate['blocked']) {
            $this->logDetection('rate_limit', '', 0);
            return $this->getErrorMessage();
        }

        $token = isset($this->request->post['_hp_token']) ? (string)$this->request->post['_hp_token'] : '';
        if ($token === '' || !isset($this->session->data['honeypot_tokens']) || !is_array($this->session->data['honeypot_tokens'])) {
            $this->logDetection('missing_session', '', 0);
            return $this->getErrorMessage();
        }

        if (!isset($this->session->data['honeypot_tokens'][$token]) || !is_array($this->session->data['honeypot_tokens'][$token])) {
            $this->logDetection('invalid_token', '', 0);
            return $this->getErrorMessage();
        }

        $entry = $this->session->data['honeypot_tokens'][$token];
        unset($this->session->data['honeypot_tokens'][$token]);

        $started = isset($entry['started']) ? (float)$entry['started'] : 0;
        $expires = isset($entry['expires']) ? (float)$entry['expires'] : 0;
        $elapsed = $started > 0 ? max(0, microtime(true) - $started) : 0;

        if ($expires > 0 && microtime(true) > $expires) {
            $this->logDetection('expired_token', '', $elapsed);
            return $this->getErrorMessage();
        }

        if (!empty($entry['ua_hash']) && !hash_equals((string)$entry['ua_hash'], $this->userAgentHash())) {
            $this->logDetection('client_mismatch', '', $elapsed);
            return $this->getErrorMessage();
        }

        $field_name = 'hp_' . substr(hash('sha256', $token . ':a'), 0, 12);
        $field_name_2 = 'hp_' . substr(hash('sha256', $token . ':b'), 0, 12);

        if (!array_key_exists($field_name, $this->request->post) || !array_key_exists($field_name_2, $this->request->post)) {
            $this->logDetection('missing_trap', '', $elapsed);
            return $this->getErrorMessage();
        }

        $trap_value = trim((string)$this->request->post[$field_name]);
        $trap_value_2 = trim((string)$this->request->post[$field_name_2]);

        if ($trap_value !== '' || $trap_value_2 !== '') {
            $this->logDetection('honeypot', trim($trap_value . ' ' . $trap_value_2), $elapsed);
            return $this->getErrorMessage();
        }

        if ($this->config->get('captcha_honeypot_js_check_status')) {
            $js_name = '_hp_js_' . substr(hash('sha256', $token . ':js'), 0, 8);
            $expected = substr(hash('sha256', $token . ':ok'), 0, 20);
            $actual = isset($this->request->post[$js_name]) ? (string)$this->request->post[$js_name] : '';

            if ($actual === '' || !hash_equals($expected, $actual)) {
                $this->logDetection('js_check', '', $elapsed);
                return $this->getErrorMessage();
            }
        }

        if ($this->config->get('captcha_honeypot_time_check_status')) {
            $min_seconds = max(0, (int)$this->config->get('captcha_honeypot_min_seconds'));
            if ($min_seconds > 0 && $elapsed < $min_seconds) {
                $this->logDetection('too_fast', '', $elapsed);
                return $this->getErrorMessage();
            }
        }

        if ($route === 'account/register' && $this->config->get('captcha_honeypot_phone_check_status')) {
            if (!$this->validateRegistrationPhone()) {
                $this->logDetection('invalid_phone', isset($this->request->post['telephone']) ? (string)$this->request->post['telephone'] : '', $elapsed);
                return $this->getErrorMessage();
            }
        }

        if ($this->shouldVerifyYandexRegistration() && !$this->verifyYandexSmartCaptcha()) {
            $this->logDetection('yandex_failed', '', $elapsed);
            return $this->getErrorMessage();
        }

        if ($route === 'account/register' && $this->config->get('captcha_honeypot_log_success_status')) {
            $this->logDetection('registration_passed', '', $elapsed);
        }
    }

    private function shouldRenderYandexRegistration() {
        $route = isset($this->request->get['route']) ? (string)$this->request->get['route'] : '';
        return $route === 'account/register'
            && $this->config->get('captcha_honeypot_yandex_status')
            && $this->config->get('captcha_honeypot_yandex_register_status')
            && !$this->isPrimaryYandexRegistration()
            && $this->isYandexReady();
    }

    private function shouldVerifyYandexRegistration() {
        return $this->shouldRenderYandexRegistration();
    }

    private function isPrimaryYandexRegistration() {
        $pages = (array)$this->config->get('config_captcha_page');
        return $this->config->get('config_captcha') === 'yandex'
            && $this->config->get('captcha_yandex_status')
            && in_array('register', $pages);
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
        if (empty($this->request->post['smart-token'])) {
            return false;
        }

        $keys = $this->getYandexKeys();
        if ($keys['secret'] === '') {
            return false;
        }

        $args = http_build_query(array(
            'secret' => $keys['secret'],
            'token' => (string)$this->request->post['smart-token'],
            'ip' => $this->getClientIp()
        ));

        $ch = curl_init('https://smartcaptcha.yandexcloud.net/validate?' . $args);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        $response = curl_exec($ch);
        $httpcode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpcode !== 200 || !$response) {
            return false;
        }

        $result = json_decode($response, true);
        return is_array($result) && isset($result['status']) && $result['status'] === 'ok';
    }

    private function validateRegistrationPhone() {
        $phone = isset($this->request->post['telephone']) ? trim((string)$this->request->post['telephone']) : '';
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

    private function registerAttempt($ip, $route) {
        $limit = max(1, min(100, (int)$this->config->get('captcha_honeypot_rate_limit')));
        $window = max(60, min(86400, (int)$this->config->get('captcha_honeypot_rate_window')));
        $block = max(60, min(86400, (int)$this->config->get('captcha_honeypot_block_seconds')));

        if (!$this->config->get('captcha_honeypot_rate_limit_status') || $ip === '') {
            return array('blocked' => false);
        }

        $this->ensureRateTable();
        $key = hash('sha256', $ip . '|' . $route);
        $query = $this->db->query("SELECT * FROM `" . DB_PREFIX . "honeypot_rate` WHERE `rate_key` = '" . $this->db->escape($key) . "' LIMIT 1");
        $now = time();

        if (!$query->num_rows) {
            $this->db->query("INSERT INTO `" . DB_PREFIX . "honeypot_rate` SET `rate_key` = '" . $this->db->escape($key) . "', ip = '" . $this->db->escape($this->limit($ip, 45)) . "', route = '" . $this->db->escape($this->limit($route, 255)) . "', attempts = 1, window_started = FROM_UNIXTIME('" . $now . "'), last_seen = NOW(), blocked_until = NULL");
            return array('blocked' => false);
        }

        $row = $query->row;
        $blocked_until = !empty($row['blocked_until']) ? strtotime($row['blocked_until']) : 0;
        if ($blocked_until && $blocked_until > $now) {
            return array('blocked' => true);
        }

        $window_started = !empty($row['window_started']) ? strtotime($row['window_started']) : 0;
        if (!$window_started || ($now - $window_started) >= $window) {
            $this->db->query("UPDATE `" . DB_PREFIX . "honeypot_rate` SET attempts = 1, window_started = NOW(), last_seen = NOW(), blocked_until = NULL WHERE `rate_key` = '" . $this->db->escape($key) . "'");
            return array('blocked' => false);
        }

        $attempts = (int)$row['attempts'] + 1;
        if ($attempts > $limit) {
            $this->db->query("UPDATE `" . DB_PREFIX . "honeypot_rate` SET attempts = '" . $attempts . "', last_seen = NOW(), blocked_until = DATE_ADD(NOW(), INTERVAL " . $block . " SECOND) WHERE `rate_key` = '" . $this->db->escape($key) . "'");
            return array('blocked' => true);
        }

        $this->db->query("UPDATE `" . DB_PREFIX . "honeypot_rate` SET attempts = '" . $attempts . "', last_seen = NOW() WHERE `rate_key` = '" . $this->db->escape($key) . "'");
        return array('blocked' => false);
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
