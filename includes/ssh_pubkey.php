<?php
/**
 * OpenSSH public keys to the SSH2 (RFC 4716) text ProFTPD mod_sftp reads.
 *
 * mod_sftp_sql compares the decoded key blob. The stored value must keep
 * the RFC 4716 line breaks. SQLite's ezSQL escape() strips those breaks,
 * so the key is quoted here instead.
 *
 * @package ProFTPd-Admin
 */

const SSH_PUBKEY_BEGIN_MARKER = '---- BEGIN SSH2 PUBLIC KEY ----';
const SSH_PUBKEY_END_MARKER = '---- END SSH2 PUBLIC KEY ----';

/**
 * Convert pasted public keys into RFC 4716 text.
 *
 * Accepts OpenSSH lines (ssh-ed25519 AAAA... comment) and existing SSH2
 * blocks. An empty value is valid and means the account has no key.
 *
 * @param string $input
 * @return array ok (bool), value (string), error (string)
 */
function ssh_pubkey_to_rfc4716($input) {
    $result = array('ok' => false, 'value' => '', 'error' => '');
    if (!is_string($input)) {
        $result['error'] = 'Invalid SSH public key.';
        return $result;
    }
    if (strpos($input, "\0") !== false) {
        $result['error'] = 'Invalid SSH public key.';
        return $result;
    }

    $input = preg_replace("/^\xEF\xBB\xBF/", '', $input);
    $input = str_replace(array("\r\n", "\r"), "\n", $input);
    $input = trim($input);
    if ($input === '') {
        $result['ok'] = true;
        return $result;
    }
    if (preg_match('/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/', $input)) {
        $result['error'] = 'Paste the public key, not the private key.';
        return $result;
    }

    $lines = explode("\n", $input);
    $count = count($lines);
    $blocks = array();
    $i = 0;
    while ($i < $count) {
        $line = trim($lines[$i]);
        if ($line === '') {
            $i++;
            continue;
        }
        if ($line === SSH_PUBKEY_BEGIN_MARKER) {
            $parsed = ssh_pubkey_consume_rfc4716($lines, $i);
        } else {
            $parsed = ssh_pubkey_parse_openssh_line($line, $i + 1);
            $i++;
        }
        if (!$parsed['ok']) {
            $result['error'] = $parsed['error'];
            return $result;
        }
        $blocks[] = $parsed;
    }

    $formatted = array();
    foreach ($blocks as $block) {
        $text = ssh_pubkey_format_rfc4716($block['b64'], $block['comment']);
        if ($text === false) {
            $result['error'] = 'SSH public key comment is too long.';
            return $result;
        }
        $formatted[] = $text;
    }

    $result['ok'] = true;
    $result['value'] = implode("\n", $formatted);
    return $result;
}

/**
 * Convert, then reject values that do not fit the active users.sshpubkey column.
 *
 * @param string $input
 * @param string $db_type
 * @return array ok (bool), value (string), error (string)
 */
function ssh_pubkey_prepare($input, $db_type) {
    $result = ssh_pubkey_to_rfc4716($input);
    if (!$result['ok']) {
        return $result;
    }
    $limit = ssh_pubkey_storage_limit($db_type);
    if (strlen($result['value']) > $limit) {
        return array(
            'ok' => false,
            'value' => '',
            'error' => 'SSH public key is too long to store (maximum '.$limit.' characters).',
        );
    }
    return $result;
}

/**
 * @param string $db_type
 * @return int
 */
function ssh_pubkey_storage_limit($db_type) {
    if (strtolower((string) $db_type) === 'sqlite3') {
        return 65535;
    }
    /* install/tables.sql uses varchar(8192), matching the mod_sftp_sql examples. */
    return 8192;
}

/**
 * Text for the user form. Stored SSH2 text is shown as OpenSSH lines.
 * Anything that is not valid SSH2 is returned unchanged.
 *
 * @param string $stored
 * @return string
 */
function ssh_pubkey_for_form($stored) {
    $stored = (string) $stored;
    if (trim($stored) === '') {
        return '';
    }
    if (strpos($stored, SSH_PUBKEY_BEGIN_MARKER) === false) {
        return $stored;
    }
    $openssh = ssh_pubkey_to_openssh($stored);
    if ($openssh === false) {
        return $stored;
    }
    return $openssh;
}

/**
 * @param string $stored
 * @return string|false OpenSSH lines, or false when the SSH2 text cannot be read
 */
function ssh_pubkey_to_openssh($stored) {
    $stored = str_replace(array("\r\n", "\r"), "\n", trim((string) $stored));
    if ($stored === '') {
        return '';
    }

    $lines = explode("\n", $stored);
    $count = count($lines);
    $out = array();
    $i = 0;
    while ($i < $count) {
        $line = trim($lines[$i]);
        if ($line === '') {
            $i++;
            continue;
        }
        if ($line !== SSH_PUBKEY_BEGIN_MARKER) {
            return false;
        }
        $parsed = ssh_pubkey_consume_rfc4716($lines, $i);
        if (!$parsed['ok']) {
            return false;
        }
        $row = $parsed['type'].' '.$parsed['b64'];
        if ($parsed['comment'] !== '') {
            $row .= ' '.$parsed['comment'];
        }
        $out[] = $row;
    }
    if (count($out) === 0) {
        return false;
    }
    return implode("\n", $out);
}

/**
 * Placeholder shown when the key field is empty.
 * Replaces the old SSH2 sample so the box matches the accepted input.
 *
 * @param string $configured
 * @return string
 */
function ssh_pubkey_form_placeholder($configured) {
    if (!is_string($configured) || $configured === '' || strpos($configured, 'BEGIN SSH2') !== false) {
        return 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@host';
    }
    return $configured;
}

/**
 * SQL string literal for a public key.
 * SQLite does not treat backslash as an escape, and the ezSQL escape helper
 * deletes newlines, so SQLite values are single-quoted with quotes doubled.
 *
 * @param string $value
 * @param string $db_type
 * @return string
 */
function ssh_pubkey_sql_literal($value, $db_type) {
    $value = (string) $value;
    if (strtolower((string) $db_type) === 'sqlite3') {
        return "'".str_replace("'", "''", $value)."'";
    }
    return '"'.addslashes($value).'"';
}

/**
 * @param array $lines
 * @param int $index
 * @return array
 */
function ssh_pubkey_consume_rfc4716(&$lines, &$index) {
    $start_line = $index + 1;
    $index++;
    $headers = array();
    $body = array();
    $saw_end = false;
    $total = count($lines);
    while ($index < $total) {
        $raw = $lines[$index];
        $index++;
        $line = trim($raw);
        if ($line === SSH_PUBKEY_END_MARKER) {
            $saw_end = true;
            break;
        }
        if ($line === '') {
            continue;
        }
        if (strlen($line) > 1023) {
            return array('ok' => false, 'error' => 'SSH2 public key line is too long.');
        }
        if (count($body) === 0 && strpos($line, ': ') !== false) {
            $parts = explode(': ', $line, 2);
            if (!preg_match('/^[A-Za-z0-9][A-Za-z0-9_-]*$/', $parts[0])) {
                return array('ok' => false, 'error' => 'Invalid SSH2 public key header on line '.$start_line.'.');
            }
            $headers[$parts[0]] = $parts[1];
            continue;
        }
        if (!preg_match('/^[A-Za-z0-9+\/=]+$/', $line)) {
            return array('ok' => false, 'error' => 'Invalid SSH2 public key on line '.$start_line.'.');
        }
        $body[] = $line;
    }
    if (!$saw_end) {
        return array('ok' => false, 'error' => 'SSH2 public key is missing the end marker.');
    }
    if (count($body) === 0) {
        return array('ok' => false, 'error' => 'SSH2 public key block is empty.');
    }

    $inspected = ssh_pubkey_inspect(implode('', $body), null);
    if ($inspected === false) {
        return array('ok' => false, 'error' => 'SSH2 public key data is not a valid public key.');
    }
    return array(
        'ok' => true,
        'error' => '',
        'type' => $inspected['type'],
        'b64' => $inspected['b64'],
        'comment' => ssh_pubkey_comment_from_headers($headers),
    );
}

/**
 * @param string $line
 * @param int $line_no
 * @return array
 */
function ssh_pubkey_parse_openssh_line($line, $line_no) {
    if (!preg_match('/^(\S+)\s+(\S+)(?:\s+(.*))?$/', $line, $matches)) {
        return array(
            'ok' => false,
            'error' => 'Invalid SSH public key on line '.$line_no.'. Paste an OpenSSH public key (ssh-ed25519 AAAA... comment) or an SSH2 public key block.',
        );
    }
    $type = $matches[1];
    $comment = isset($matches[3]) ? $matches[3] : '';
    if (!preg_match('/^[A-Za-z0-9][A-Za-z0-9@._+-]*$/', $type)) {
        return array('ok' => false, 'error' => 'Invalid SSH public key type on line '.$line_no.'.');
    }
    if (preg_match('/[\x00-\x1F\x7F]/', $comment)) {
        return array('ok' => false, 'error' => 'SSH public key comment contains unsupported characters.');
    }
    $inspected = ssh_pubkey_inspect($matches[2], $type);
    if ($inspected === false) {
        return array(
            'ok' => false,
            'error' => 'SSH public key on line '.$line_no.' is truncated or the key type does not match the key data.',
        );
    }
    return array(
        'ok' => true,
        'error' => '',
        'type' => $inspected['type'],
        'b64' => $inspected['b64'],
        'comment' => $comment,
    );
}

/**
 * Decode a public key blob and read the key type from its first SSH string.
 *
 * @param string $b64
 * @param string|null $expected_type
 * @return array|false
 */
function ssh_pubkey_inspect($b64, $expected_type) {
    $raw = base64_decode($b64, true);
    if ($raw === false || $raw === '') {
        return false;
    }
    if (strlen($raw) < 5) {
        return false;
    }
    $unpacked = unpack('Nlen', substr($raw, 0, 4));
    $length = $unpacked['len'];
    if ($length < 1 || $length > 128 || strlen($raw) <= 4 + $length) {
        return false;
    }
    $type = substr($raw, 4, $length);
    if (!preg_match('/^[A-Za-z0-9][A-Za-z0-9@._+-]*$/', $type)) {
        return false;
    }
    if ($expected_type !== null && $expected_type !== $type) {
        return false;
    }
    return array('type' => $type, 'b64' => base64_encode($raw));
}

/**
 * @param array $headers
 * @return string
 */
function ssh_pubkey_comment_from_headers($headers) {
    foreach ($headers as $tag => $value) {
        if (strcasecmp($tag, 'Comment') === 0) {
            return ssh_pubkey_unquote_comment($value);
        }
    }
    return '';
}

/**
 * @param string $value
 * @return string
 */
function ssh_pubkey_unquote_comment($value) {
    if (strlen($value) >= 2 && $value[0] === '"' && substr($value, -1) === '"') {
        $inner = substr($value, 1, strlen($value) - 2);
        $out = '';
        $length = strlen($inner);
        for ($i = 0; $i < $length; $i++) {
            if ($inner[$i] === '\\' && $i + 1 < $length) {
                $out .= $inner[$i + 1];
                $i++;
            } else {
                $out .= $inner[$i];
            }
        }
        return $out;
    }
    return $value;
}

/**
 * @param string $b64
 * @param string $comment
 * @return string|false
 */
function ssh_pubkey_format_rfc4716($b64, $comment) {
    $lines = array(SSH_PUBKEY_BEGIN_MARKER);
    if ($comment !== '') {
        $escaped = str_replace(array('\\', '"'), array('\\\\', '\\"'), $comment);
        $header = 'Comment: "'.$escaped.'"';
        /* mod_sftp_sql drops lines longer than its 1024-byte read buffer. */
        if (strlen($header) > 1023) {
            return false;
        }
        $lines[] = $header;
    }
    $wrapped = rtrim(chunk_split($b64, 70, "\n"), "\n");
    foreach (explode("\n", $wrapped) as $part) {
        $lines[] = $part;
    }
    $lines[] = SSH_PUBKEY_END_MARKER;
    return implode("\n", $lines);
}
