<?php
class ControllerExtensionCaptchaHoneypot extends Controller {
    const VERSION = '1.2.0';
    private $error = array();

    public function index() {
        $this->load->language('extension/captcha/honeypot');
        $this->document->setTitle($this->language->get('heading_title'));

        $this->load->model('setting/setting');
        $this->load->model('extension/captcha/honeypot');
        $this->model_extension_captcha_honeypot->install();

        if (($this->request->server['REQUEST_METHOD'] == 'POST') && $this->validate()) {
            $settings = array(
                'captcha_honeypot_status' => !empty($this->request->post['captcha_honeypot_status']) ? 1 : 0,
                'captcha_honeypot_min_seconds' => isset($this->request->post['captcha_honeypot_min_seconds']) ? max(0, min(30, (int)$this->request->post['captcha_honeypot_min_seconds'])) : 5,
                'captcha_honeypot_time_check_status' => !empty($this->request->post['captcha_honeypot_time_check_status']) ? 1 : 0,
                'captcha_honeypot_js_check_status' => !empty($this->request->post['captcha_honeypot_js_check_status']) ? 1 : 0,
                'captcha_honeypot_token_ttl' => isset($this->request->post['captcha_honeypot_token_ttl']) ? max(60, min(7200, (int)$this->request->post['captcha_honeypot_token_ttl'])) : 1800,
                'captcha_honeypot_rate_limit_status' => !empty($this->request->post['captcha_honeypot_rate_limit_status']) ? 1 : 0,
                'captcha_honeypot_rate_limit' => isset($this->request->post['captcha_honeypot_rate_limit']) ? max(1, min(100, (int)$this->request->post['captcha_honeypot_rate_limit'])) : 6,
                'captcha_honeypot_rate_window' => isset($this->request->post['captcha_honeypot_rate_window']) ? max(60, min(86400, (int)$this->request->post['captcha_honeypot_rate_window'])) : 900,
                'captcha_honeypot_block_seconds' => isset($this->request->post['captcha_honeypot_block_seconds']) ? max(60, min(86400, (int)$this->request->post['captcha_honeypot_block_seconds'])) : 1800,
                'captcha_honeypot_log_status' => !empty($this->request->post['captcha_honeypot_log_status']) ? 1 : 0,
                'captcha_honeypot_retention_days' => isset($this->request->post['captcha_honeypot_retention_days']) ? max(1, min(3650, (int)$this->request->post['captcha_honeypot_retention_days'])) : 90
            );

            $this->model_setting_setting->editSetting('captcha_honeypot', $settings);
            $this->model_extension_captcha_honeypot->purgeOldLogs($settings['captcha_honeypot_retention_days']);
            $this->session->data['success'] = $this->language->get('text_success');
            $this->response->redirect($this->url->link('extension/captcha/honeypot', 'user_token=' . $this->session->data['user_token'], true));
        }

        $data['error_warning'] = isset($this->error['warning']) ? $this->error['warning'] : '';
        if (!$data['error_warning'] && isset($this->session->data['error_warning'])) {
            $data['error_warning'] = $this->session->data['error_warning'];
            unset($this->session->data['error_warning']);
        }

        $data['success'] = isset($this->session->data['success']) ? $this->session->data['success'] : '';
        unset($this->session->data['success']);

        $defaults = array(
            'captcha_honeypot_status' => 0,
            'captcha_honeypot_min_seconds' => 5,
            'captcha_honeypot_time_check_status' => 1,
            'captcha_honeypot_js_check_status' => 1,
            'captcha_honeypot_token_ttl' => 1800,
            'captcha_honeypot_rate_limit_status' => 1,
            'captcha_honeypot_rate_limit' => 6,
            'captcha_honeypot_rate_window' => 900,
            'captcha_honeypot_block_seconds' => 1800,
            'captcha_honeypot_log_status' => 1,
            'captcha_honeypot_retention_days' => 90
        );

        foreach ($defaults as $key => $default) {
            if (isset($this->request->post[$key])) {
                $data[$key] = $this->request->post[$key];
            } else {
                $value = $this->config->get($key);
                $data[$key] = ($value === null || $value === '') ? $default : $value;
            }
        }

        $filter_email = isset($this->request->get['filter_email']) ? trim($this->request->get['filter_email']) : '';
        $filter_ip = isset($this->request->get['filter_ip']) ? trim($this->request->get['filter_ip']) : '';
        $filter_reason = isset($this->request->get['filter_reason']) ? trim($this->request->get['filter_reason']) : '';
        $page = isset($this->request->get['page']) ? max(1, (int)$this->request->get['page']) : 1;
        $limit = 25;

        $filter_data = array(
            'filter_email' => $filter_email,
            'filter_ip' => $filter_ip,
            'filter_reason' => $filter_reason,
            'start' => ($page - 1) * $limit,
            'limit' => $limit
        );

        $data['logs'] = $this->model_extension_captcha_honeypot->getLogs($filter_data);
        $data['log_total'] = $this->model_extension_captcha_honeypot->getTotalLogs($filter_data);
        $data['stats'] = $this->model_extension_captcha_honeypot->getStats();
        $data['filter_email'] = $filter_email;
        $data['filter_ip'] = $filter_ip;
        $data['filter_reason'] = $filter_reason;
        $data['user_token'] = $this->session->data['user_token'];

        $url = '';
        if ($filter_email !== '') $url .= '&filter_email=' . urlencode($filter_email);
        if ($filter_ip !== '') $url .= '&filter_ip=' . urlencode($filter_ip);
        if ($filter_reason !== '') $url .= '&filter_reason=' . urlencode($filter_reason);

        $pagination = new Pagination();
        $pagination->total = $data['log_total'];
        $pagination->page = $page;
        $pagination->limit = $limit;
        $pagination->url = $this->url->link('extension/captcha/honeypot', 'user_token=' . $this->session->data['user_token'] . $url . '&page={page}', true);
        $data['pagination'] = $pagination->render();

        $pages = $data['log_total'] ? (int)ceil($data['log_total'] / $limit) : 0;
        $data['results'] = sprintf($this->language->get('text_pagination'), $data['log_total'] ? (($page - 1) * $limit) + 1 : 0, min($page * $limit, $data['log_total']), $data['log_total'], $pages);

        $data['breadcrumbs'] = array();
        $data['breadcrumbs'][] = array('text' => $this->language->get('text_home'), 'href' => $this->url->link('common/dashboard', 'user_token=' . $this->session->data['user_token'], true));
        $data['breadcrumbs'][] = array('text' => $this->language->get('text_extension'), 'href' => $this->url->link('marketplace/extension', 'user_token=' . $this->session->data['user_token'] . '&type=captcha', true));
        $data['breadcrumbs'][] = array('text' => $this->language->get('heading_title'), 'href' => $this->url->link('extension/captcha/honeypot', 'user_token=' . $this->session->data['user_token'], true));

        $data['action'] = $this->url->link('extension/captcha/honeypot', 'user_token=' . $this->session->data['user_token'], true);
        $data['filter_action'] = 'index.php';
        $data['clear'] = $this->url->link('extension/captcha/honeypot/clear', 'user_token=' . $this->session->data['user_token'], true);
        $data['cancel'] = $this->url->link('marketplace/extension', 'user_token=' . $this->session->data['user_token'] . '&type=captcha', true);

        $data['donate_url'] = 'https://boosty.to/matveevd/donate';
        $data['donate_qr'] = 'view/image/extension/captcha/honeypot_donate.png';
        $data['version'] = self::VERSION;

        $data['header'] = $this->load->controller('common/header');
        $data['column_left'] = $this->load->controller('common/column_left');
        $data['footer'] = $this->load->controller('common/footer');
        $this->response->setOutput($this->load->view('extension/captcha/honeypot', $data));
    }

    public function install() {
        $this->load->model('user/user_group');
        $this->load->model('setting/setting');
        $this->load->model('extension/captcha/honeypot');

        $this->model_user_user_group->addPermission($this->user->getGroupId(), 'access', 'extension/captcha/honeypot');
        $this->model_user_user_group->addPermission($this->user->getGroupId(), 'modify', 'extension/captcha/honeypot');
        $this->model_extension_captcha_honeypot->install();

        $this->model_setting_setting->editSetting('captcha_honeypot', array(
            'captcha_honeypot_status' => 0,
            'captcha_honeypot_min_seconds' => 5,
            'captcha_honeypot_time_check_status' => 1,
            'captcha_honeypot_js_check_status' => 1,
            'captcha_honeypot_token_ttl' => 1800,
            'captcha_honeypot_rate_limit_status' => 1,
            'captcha_honeypot_rate_limit' => 6,
            'captcha_honeypot_rate_window' => 900,
            'captcha_honeypot_block_seconds' => 1800,
            'captcha_honeypot_log_status' => 1,
            'captcha_honeypot_retention_days' => 90
        ));
    }

    public function uninstall() {
        $this->load->model('setting/setting');
        $this->model_setting_setting->deleteSetting('captcha_honeypot');
    }

    public function clear() {
        $this->load->language('extension/captcha/honeypot');
        if (!$this->user->hasPermission('modify', 'extension/captcha/honeypot')) {
            $this->session->data['error_warning'] = $this->language->get('error_permission');
        } else {
            $this->load->model('extension/captcha/honeypot');
            $this->model_extension_captcha_honeypot->install();
            $this->model_extension_captcha_honeypot->clearLogs();
            $this->session->data['success'] = $this->language->get('text_log_cleared');
        }
        $this->response->redirect($this->url->link('extension/captcha/honeypot', 'user_token=' . $this->session->data['user_token'], true));
    }

    protected function validate() {
        if (!$this->user->hasPermission('modify', 'extension/captcha/honeypot')) {
            $this->error['warning'] = $this->language->get('error_permission');
        }
        return !$this->error;
    }
}
