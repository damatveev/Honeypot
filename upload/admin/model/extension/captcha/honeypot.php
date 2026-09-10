<?php
class ModelExtensionCaptchaHoneypot extends Model {
    public function install() {
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
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8");

        $this->db->query("CREATE TABLE IF NOT EXISTS `" . DB_PREFIX . "honeypot_rate` (
            `rate_key` CHAR(64) NOT NULL,
            `ip` VARCHAR(45) NOT NULL DEFAULT '',
            `route` VARCHAR(255) NOT NULL DEFAULT '',
            `attempts` INT(11) NOT NULL DEFAULT '0',
            `window_started` DATETIME NOT NULL,
            `last_seen` DATETIME NOT NULL,
            `blocked_until` DATETIME NULL,
            PRIMARY KEY (`rate_key`),
            KEY `last_seen` (`last_seen`),
            KEY `blocked_until` (`blocked_until`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8");
    }

    public function getLogs($data = array()) {
        $sql = "SELECT * FROM `" . DB_PREFIX . "honeypot_log` WHERE 1";
        if (!empty($data['filter_email'])) $sql .= " AND email LIKE '%" . $this->db->escape($data['filter_email']) . "%'";
        if (!empty($data['filter_ip'])) $sql .= " AND ip LIKE '%" . $this->db->escape($data['filter_ip']) . "%'";
        if (!empty($data['filter_reason'])) $sql .= " AND reason = '" . $this->db->escape($data['filter_reason']) . "'";
        $sql .= " ORDER BY honeypot_log_id DESC";
        $start = isset($data['start']) ? max(0, (int)$data['start']) : 0;
        $limit = isset($data['limit']) ? max(1, (int)$data['limit']) : 25;
        $sql .= " LIMIT " . $start . "," . $limit;
        return $this->db->query($sql)->rows;
    }

    public function getTotalLogs($data = array()) {
        $sql = "SELECT COUNT(*) AS total FROM `" . DB_PREFIX . "honeypot_log` WHERE 1";
        if (!empty($data['filter_email'])) $sql .= " AND email LIKE '%" . $this->db->escape($data['filter_email']) . "%'";
        if (!empty($data['filter_ip'])) $sql .= " AND ip LIKE '%" . $this->db->escape($data['filter_ip']) . "%'";
        if (!empty($data['filter_reason'])) $sql .= " AND reason = '" . $this->db->escape($data['filter_reason']) . "'";
        return (int)$this->db->query($sql)->row['total'];
    }

    public function getStats() {
        $query = $this->db->query("SELECT COUNT(*) AS total, SUM(CASE WHEN DATE(date_added) = CURDATE() THEN 1 ELSE 0 END) AS today, COUNT(DISTINCT NULLIF(ip, '')) AS unique_ip, COUNT(DISTINCT NULLIF(email, '')) AS unique_email FROM `" . DB_PREFIX . "honeypot_log`");
        return array(
            'total' => isset($query->row['total']) ? (int)$query->row['total'] : 0,
            'today' => isset($query->row['today']) ? (int)$query->row['today'] : 0,
            'unique_ip' => isset($query->row['unique_ip']) ? (int)$query->row['unique_ip'] : 0,
            'unique_email' => isset($query->row['unique_email']) ? (int)$query->row['unique_email'] : 0
        );
    }

    public function purgeOldLogs($days) {
        $days = max(1, (int)$days);
        $this->db->query("DELETE FROM `" . DB_PREFIX . "honeypot_log` WHERE date_added < DATE_SUB(NOW(), INTERVAL " . $days . " DAY)");
        $this->db->query("DELETE FROM `" . DB_PREFIX . "honeypot_rate` WHERE last_seen < DATE_SUB(NOW(), INTERVAL 2 DAY)");
    }

    public function clearLogs() {
        $this->db->query("TRUNCATE TABLE `" . DB_PREFIX . "honeypot_log`");
        $this->db->query("TRUNCATE TABLE `" . DB_PREFIX . "honeypot_rate`");
    }
}
