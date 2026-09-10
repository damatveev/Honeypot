<?php
class ControllerExtensionCaptchaHoneypot extends Controller {
    public function index($error = array()) {
        if (!$this->config->get('captcha_honeypot_status')) {
            return '';
        }

        $token = $this->makeToken();

        if (!isset($this->session->data['honeypot_tokens']) || !is_array($this->session->data['honeypot_tokens'])) {
            $this->session->data['honeypot_tokens'] = array();
        }

        if (count($this->session->data['honeypot_tokens']) > 20) {
            $this->session->data['honeypot_tokens'] = array_slice($this->session->data['honeypot_tokens'], -10, null, true);
        }

        $this->session->data['honeypot_tokens'][$token] = microtime(true);

        $data['token'] = $token;
        $data['field_name'] = 'hp_' . substr(hash('sha256', $token), 0, 12);

        return $this->load->view('extension/captcha/honeypot', $data);
    }

    public function validate() {
        if (!$this->config->get('captcha_honeypot_status')) {
            return;
        }

        $token = isset($this->request->post['_hp_token']) ? (string)$this->request->post['_hp_token'] : '';
        $field_name = $token !== '' ? 'hp_' . substr(hash('sha256', $token), 0, 12) : '';
        $trap_value = ($field_name !== '' && isset($this->request->post[$field_name])) ? trim((string)$this->request->post[$field_name]) : '';

        $started = null;
        if ($token !== '' && isset($this->session->data['honeypot_tokens'][$token])) {
            $started = (float)$this->session->data['honeypot_tokens'][$token];
            unset($this->session->data['honeypot_tokens'][$token]);
        }

        $elapsed = $started !== null ? max(0, microtime(true) - $started) : 0;

        if ($token === '' || $started === null) {
            $this->logDetection('invalid_token', $trap_value, $elapsed);
            return $this->getErrorMessage();
        }

        if ($trap_value !== '') {
            $this->logDetection('honeypot', $trap_value, $elapsed);
            return $this->getErrorMessage();
        }

        if ($this->config->get('captcha_honeypot_time_check_status')) {
            $min_seconds = (int)$this->config->get('captcha_honeypot_min_seconds');

            if ($min_seconds > 0 && $elapsed < $min_seconds) {
                $this->logDetection('too_fast', '', $elapsed);
                return $this->getErrorMessage();
            }
        }
    }

    private function getErrorMessage() {
        $this->load->language('extension/captcha/honeypot');
        return $this->language->get('error_captcha');
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
        $ip = isset($this->request->server['REMOTE_ADDR']) ? (string)$this->request->server['REMOTE_ADDR'] : '';
        $user_agent = isset($this->request->server['HTTP_USER_AGENT']) ? (string)$this->request->server['HTTP_USER_AGENT'] : '';
        $request_uri = isset($this->request->server['REQUEST_URI']) ? (string)$this->request->server['REQUEST_URI'] : '';

        $this->ensureLogTable();

        $this->db->query("INSERT INTO `" . DB_PREFIX . "honeypot_log` SET
            store_id = '" . (int)$this->config->get('config_store_id') . "',
            route = '" . $this->db->escape($this->limit($route, 255)) . "',
            email = '" . $this->db->escape($this->limit($email, 255)) . "',
            name = '" . $this->db->escape($this->limit($name, 255)) . "',
            ip = '" . $this->db->escape($this->limit($ip, 45)) . "',
            user_agent = '" . $this->db->escape($this->limit($user_agent, 512)) . "',
            reason = '" . $this->db->escape($this->limit($reason, 32)) . "',
            trap_value = '" . $this->db->escape($this->limit($trap_value, 255)) . "',
            elapsed = '" . (float)$elapsed . "',
            request_uri = '" . $this->db->escape($this->limit($request_uri, 512)) . "',
            date_added = NOW()");
    }

    private function ensureLogTable() {
        $this->db->query("CREATE TABLE IF NOT EXISTS `" . DB_PREFIX . "honeypot_log` (
            `honeypot_log_id` INT(11) NOT NULL AUTO_INCREMENT,
            `store_id` INT(11) NOT NULL DEFAULT '0',
            `route` VARCHAR(255) NOT NULL DEFAULT '',
            `email` VARCHAR(255) NOT NULL DEFAULT '',
            `name` VARCHAR(255) NOT NULL DEFAULT '',
            `ip` VARCHAR(45) NOT NULL DEFAULT '',
            `user_agent` VARCHAR(512) NOT NULL DEFAULT '',
            `reason` VARCHAR(32) NOT NULL DEFAULT '',
            `trap_value` VARCHAR(255) NOT NULL DEFAULT '',
            `elapsed` DECIMAL(10,3) NOT NULL DEFAULT '0.000',
            `request_uri` VARCHAR(512) NOT NULL DEFAULT '',
            `date_added` DATETIME NOT NULL,
            PRIMARY KEY (`honeypot_log_id`),
            KEY `email` (`email`),
            KEY `ip` (`ip`),
            KEY `reason` (`reason`),
            KEY `date_added` (`date_added`)
        ) ENGINE=MyISAM DEFAULT CHARSET=utf8");
    }

    private function limit($value, $length) {
        $value = (string)$value;

        if (function_exists('utf8_substr')) {
            return utf8_substr($value, 0, $length);
        }

        return substr($value, 0, $length);
    }
}
