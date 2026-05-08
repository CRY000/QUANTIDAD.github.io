<?php
/**
 * ╔══════════════════════════════════════════════════════╗
 * ║          QANTIDAD — Form Handler v2.0               ║
 * ║          Resend API · PHP · Secure Backend          ║
 * ╚══════════════════════════════════════════════════════╝
 *
 * INSTALACIÓN EN cPanel:
 *   1. Subir este archivo a la raíz del sitio (junto a index.html)
 *   2. Crear la carpeta /tmp/ con permisos 755
 *   3. Editar el bloque CONFIG con tus datos reales
 *   4. No requiere Composer — usa cURL nativo de PHP
 */

declare(strict_types=1);

// ════════════════════════════════════════════════════════
//  CONFIG — EDITA SOLO ESTE BLOQUE
// ════════════════════════════════════════════════════════
const RESEND_API_KEY  = 're_iBnh63i6_4ueehcJM5HgcAf3v2j735qWa';  // Tu API Key de Resend
const EMAIL_TO        = 'javierflorezwork@gmail.com';         // Tu correo destino
const EMAIL_FROM      = 'noreply@qantidad.com.au';      // Dominio verificado en Resend
const EMAIL_FROM_NAME = 'Qantidad Web';
const SITE_DOMAIN     = 'https://qantidad.com.au';      // Sin barra final

const MAX_FILE_SIZE_MB  = 10;
const MAX_TOTAL_SIZE_MB = 35;
const MAX_FILES         = 5;

const RATE_LIMIT_MAX    = 5;
const RATE_LIMIT_WINDOW = 3600;
const RATE_LIMIT_FILE   = __DIR__ . '/tmp/rl_cache.json';

const ALLOWED_EXTENSIONS = ['pdf', 'dwg', 'dxf', 'rvt', 'png', 'jpg', 'jpeg', 'zip'];
const SAFE_MIME_TYPES    = [
    'application/pdf', 'image/jpeg', 'image/png',
    'application/zip', 'application/x-zip-compressed',
    'application/octet-stream',
];
// ════════════════════════════════════════════════════════


// ── 1. Headers de seguridad ──────────────────────────────────
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Cache-Control: no-store, no-cache, must-revalidate');

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
$allowedOrigins = [SITE_DOMAIN, 'http://localhost', 'http://127.0.0.1'];
if (in_array($origin, $allowedOrigins, true)) {
    header("Access-Control-Allow-Origin: $origin");
} else {
    header('Access-Control-Allow-Origin: ' . SITE_DOMAIN);
}
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, X-Requested-With');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }
if ($_SERVER['REQUEST_METHOD'] !== 'POST')    { respond(false, 'Method not allowed.', 405); }
if (($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '') !== 'XMLHttpRequest') {
    respond(false, 'Invalid request.', 403);
}


// ── 2. Rate limiting ─────────────────────────────────────────
function checkRateLimit(): void
{
    $dir = dirname(RATE_LIMIT_FILE);
    if (!is_dir($dir)) mkdir($dir, 0755, true);

    $ip = $_SERVER['HTTP_CF_CONNECTING_IP']
        ?? $_SERVER['HTTP_X_FORWARDED_FOR']
        ?? $_SERVER['REMOTE_ADDR']
        ?? 'unknown';
    $ipHash = hash('sha256', trim(explode(',', $ip)[0]));
    $now    = time();
    $data   = file_exists(RATE_LIMIT_FILE)
            ? (json_decode(file_get_contents(RATE_LIMIT_FILE), true) ?? [])
            : [];

    foreach ($data as $k => $v) {
        if ($now - $v['first'] > RATE_LIMIT_WINDOW) unset($data[$k]);
    }

    $data[$ipHash] = $data[$ipHash] ?? ['count' => 0, 'first' => $now];
    $data[$ipHash]['count']++;

    if ($data[$ipHash]['count'] > RATE_LIMIT_MAX) {
        file_put_contents(RATE_LIMIT_FILE, json_encode($data), LOCK_EX);
        respond(false, 'Too many requests. Please try again in an hour.', 429);
    }
    file_put_contents(RATE_LIMIT_FILE, json_encode($data), LOCK_EX);
}
checkRateLimit();


// ── 3. Anti-spam: honeypot + timestamp ──────────────────────
if (!empty($_POST['website'])) { respond(true, 'Message received.'); } // honeypot silencioso

$ts  = (int)($_POST['_ts'] ?? 0);
$age = time() - $ts;
if ($ts === 0 || $age < 3 || $age > 3600) {
    respond(false, 'Session expired. Please reload the page and try again.', 400);
}


// ── 4. Sanitizar y validar campos ───────────────────────────
function s(string $v): string {
    return htmlspecialchars(strip_tags(trim($v)), ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

$firstName   = s($_POST['first_name']   ?? '');
$lastName    = s($_POST['last_name']    ?? '');
$rawEmail    = trim($_POST['email']     ?? '');
$email       = filter_var($rawEmail, FILTER_VALIDATE_EMAIL);
$phone       = s($_POST['phone']        ?? '');
$service     = s($_POST['service']      ?? '');
$projectType = s($_POST['project_type'] ?? '');
$details     = s($_POST['details']      ?? '');
$formSource  = s($_POST['form_source']  ?? 'Website');

$errors = [];
if (!$firstName)                     $errors[] = 'First name is required.';
if (!$lastName)                      $errors[] = 'Last name is required.';
if (!$email)                         $errors[] = 'A valid email address is required.';
if (!$phone)                         $errors[] = 'Phone number is required.';
if (!$service || str_starts_with($service, 'Select')) {
                                     $errors[] = 'Please select a service.';
}
if (strlen($firstName) > 80)        $errors[] = 'First name is too long.';
if (strlen($lastName)  > 80)        $errors[] = 'Last name is too long.';
if (strlen($phone)     > 30)        $errors[] = 'Phone number is too long.';
if (strlen($details)   > 3000)      $errors[] = 'Project details too long (max 3000 chars).';
if (!empty($errors)) respond(false, implode(' ', $errors), 422);

$fullName = "$firstName $lastName";


// ── 5. Procesar archivos adjuntos ───────────────────────────
$attachments = [];
$totalBytes  = 0;

if (!empty($_FILES['files']['name'][0])) {
    $files = $_FILES['files'];
    $count = count($files['name']);

    if ($count > MAX_FILES) respond(false, 'Maximum ' . MAX_FILES . ' files allowed.', 422);

    for ($i = 0; $i < $count; $i++) {
        if ($files['error'][$i] === UPLOAD_ERR_NO_FILE) continue;
        if ($files['error'][$i] !== UPLOAD_ERR_OK)
            respond(false, 'Upload error on file #' . ($i + 1) . '. Please try again.', 422);

        $safeName = preg_replace('/[^a-zA-Z0-9._\-]/', '_', basename($files['name'][$i]));
        $ext      = strtolower(pathinfo($safeName, PATHINFO_EXTENSION));
        $size     = (int)$files['size'][$i];
        $tmp      = $files['tmp_name'][$i];

        if (!in_array($ext, ALLOWED_EXTENSIONS, true))
            respond(false, "Format '.$ext' not allowed. Accepted: " . implode(', ', ALLOWED_EXTENSIONS), 422);

        if ($size > MAX_FILE_SIZE_MB * 1024 * 1024)
            respond(false, "'$safeName' exceeds the " . MAX_FILE_SIZE_MB . " MB file limit.", 422);

        $totalBytes += $size;
        if ($totalBytes > MAX_TOTAL_SIZE_MB * 1024 * 1024)
            respond(false, 'Total files exceed ' . MAX_TOTAL_SIZE_MB . ' MB.', 422);

        // Validación MIME real (libmagic)
        if (function_exists('finfo_open')) {
            $mime = (new finfo(FILEINFO_MIME_TYPE))->file($tmp);
            $strictExts = ['pdf', 'jpg', 'jpeg', 'png'];
            if (in_array($ext, $strictExts, true) && !in_array($mime, SAFE_MIME_TYPES, true))
                respond(false, "'$safeName' failed security validation.", 422);
        }

        $content = file_get_contents($tmp);
        if ($content === false) respond(false, "Could not read '$safeName'. Please try again.", 500);

        $attachments[] = ['filename' => $safeName, 'content' => base64_encode($content)];
    }
}


// ── 6. Construir email HTML ──────────────────────────────────
$submittedAt = date('D, d M Y \a\t H:i T');
$fileCount   = count($attachments);

$filesHtml = $fileCount > 0
    ? "<strong style='color:#0d1f3c;font-size:14px;'>$fileCount file(s) attached:</strong><ul style='margin:8px 0 0;padding-left:18px;'>"
      . implode('', array_map(fn($a) => "<li style='color:#5a6278;font-size:14px;padding:2px 0;'>" . htmlspecialchars($a['filename']) . "</li>", $attachments))
      . "</ul>"
    : "<em style='color:#9ca3af;font-size:14px;'>No files attached.</em>";

$detailsHtml = $details
    ? "<p style='margin:0;font-size:14px;color:#5a6278;line-height:1.7;'>" . nl2br($details) . "</p>"
    : "<em style='color:#9ca3af;font-size:14px;'>Not provided.</em>";

$ptHtml = $projectType ?: '<em style="color:#9ca3af;">Not specified</em>';

// Prefill para el botón "Reply to"
$replySubject = rawurlencode("Re: Your Quote Request – $service");
$replyBody    = rawurlencode("Hi $firstName,\n\nThank you for reaching out to Qantidad. We've received your quote request and will be in touch within 24–48 hours.\n\nKind regards,\nThe Qantidad Team");

$htmlBody = <<<HTML
<!DOCTYPE html><html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>New Quote – Qantidad</title></head>
<body style="margin:0;padding:0;background:#f7f8fa;font-family:Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#f7f8fa;padding:32px 16px;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" border="0" style="background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 32px rgba(0,0,0,0.10);max-width:600px;width:100%;">

  <tr><td style="background:#0d1f3c;padding:24px 36px;">
    <table width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
      <td><span style="font-size:22px;font-weight:800;color:#fff;letter-spacing:1px;">&#9650; QANTIDAD</span><br>
          <span style="font-size:11px;color:rgba(255,255,255,0.5);letter-spacing:2px;text-transform:uppercase;">Quantity Estimating</span></td>
      <td align="right" style="vertical-align:middle;">
        <span style="display:inline-block;background:#f07c1c;color:#fff;font-size:11px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;padding:5px 12px;border-radius:100px;">New Quote Request</span>
      </td>
    </tr></table>
  </td></tr>

  <tr><td style="background:#f07c1c;padding:12px 36px;">
    <p style="margin:0;color:#fff;font-size:14px;font-weight:700;">&#128203;&nbsp; New quote request received from {$formSource}</p>
  </td></tr>

  <tr><td style="padding:32px 36px;">

    <p style="margin:0 0 14px;font-size:11px;font-weight:700;color:#f07c1c;letter-spacing:2px;text-transform:uppercase;">Client Information</p>
    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:22px;">
      <tr>
        <td width="50%" style="padding:0 6px 10px 0;vertical-align:top;">
          <div style="background:#f7f8fa;border-radius:10px;padding:12px 14px;">
            <p style="margin:0 0 3px;font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Full Name</p>
            <p style="margin:0;font-size:15px;color:#0d1f3c;font-weight:700;">{$fullName}</p>
          </div>
        </td>
        <td width="50%" style="padding:0 0 10px 6px;vertical-align:top;">
          <div style="background:#f7f8fa;border-radius:10px;padding:12px 14px;">
            <p style="margin:0 0 3px;font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Email</p>
            <p style="margin:0;font-size:14px;color:#0d1f3c;font-weight:700;word-break:break-word;">{$email}</p>
          </div>
        </td>
      </tr>
      <tr>
        <td width="50%" style="padding:0 6px 0 0;vertical-align:top;">
          <div style="background:#f7f8fa;border-radius:10px;padding:12px 14px;">
            <p style="margin:0 0 3px;font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Phone</p>
            <p style="margin:0;font-size:15px;color:#0d1f3c;font-weight:700;">{$phone}</p>
          </div>
        </td>
        <td width="50%" style="padding:0 0 0 6px;vertical-align:top;">
          <div style="background:#f7f8fa;border-radius:10px;padding:12px 14px;">
            <p style="margin:0 0 3px;font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Submitted</p>
            <p style="margin:0;font-size:13px;color:#0d1f3c;font-weight:600;">{$submittedAt}</p>
          </div>
        </td>
      </tr>
    </table>

    <p style="margin:0 0 14px;font-size:11px;font-weight:700;color:#f07c1c;letter-spacing:2px;text-transform:uppercase;">Project Details</p>
    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:14px;">
      <tr>
        <td width="50%" style="padding:0 6px 10px 0;vertical-align:top;">
          <div style="background:#f7f8fa;border-radius:10px;padding:12px 14px;">
            <p style="margin:0 0 3px;font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Service Required</p>
            <p style="margin:0;font-size:15px;color:#0d1f3c;font-weight:700;">{$service}</p>
          </div>
        </td>
        <td width="50%" style="padding:0 0 10px 6px;vertical-align:top;">
          <div style="background:#f7f8fa;border-radius:10px;padding:12px 14px;">
            <p style="margin:0 0 3px;font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Project Type</p>
            <p style="margin:0;font-size:15px;color:#0d1f3c;font-weight:700;">{$ptHtml}</p>
          </div>
        </td>
      </tr>
    </table>
    <div style="background:#f7f8fa;border-radius:10px;padding:14px 16px;margin-bottom:22px;">
      <p style="margin:0 0 6px;font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Project Notes</p>
      {$detailsHtml}
    </div>

    <p style="margin:0 0 14px;font-size:11px;font-weight:700;color:#f07c1c;letter-spacing:2px;text-transform:uppercase;">Attached Files</p>
    <div style="background:#f7f8fa;border-radius:10px;padding:14px 16px;margin-bottom:26px;">{$filesHtml}</div>

    <table width="100%" cellpadding="0" cellspacing="0" border="0">
      <tr><td style="background:#0d1f3c;border-radius:10px;padding:18px 22px;">
        <p style="margin:0 0 12px;font-size:13px;color:rgba(255,255,255,0.7);">Reply directly to this client:</p>
        <a href="mailto:{$email}?subject={$replySubject}&body={$replyBody}"
           style="display:inline-block;background:#f07c1c;color:#fff;font-weight:700;font-size:14px;
                  padding:12px 24px;border-radius:8px;text-decoration:none;">
          ✉ Reply to {$firstName} &#8594;
        </a>
      </td></tr>
    </table>

  </td></tr>
  <tr><td style="background:#f7f8fa;border-top:1px solid #eef0f4;padding:16px 36px;text-align:center;">
    <p style="margin:0;font-size:12px;color:#9ca3af;">Automated notification from <strong>qantidad.com.au</strong> &middot; Do not reply to this address</p>
  </td></tr>
</table>
</td></tr></table>
</body></html>
HTML;

$textBody = "NEW QUOTE — QANTIDAD\n"
    . str_repeat('-', 40) . "\n"
    . "Source:    $formSource\n"
    . "Date:      $submittedAt\n\n"
    . "NAME:      $fullName\n"
    . "EMAIL:     $email\n"
    . "PHONE:     $phone\n\n"
    . "SERVICE:   $service\n"
    . "TYPE:      " . ($projectType ?: 'Not specified') . "\n"
    . "NOTES:     " . ($details ?: 'Not provided') . "\n\n"
    . "FILES:     " . ($fileCount > 0
        ? implode(', ', array_column($attachments, 'filename'))
        : 'None') . "\n";


// ── 7. Enviar con la API de Resend ───────────────────────────
$payload = [
    'from'     => EMAIL_FROM_NAME . ' <' . EMAIL_FROM . '>',
    'to'       => [EMAIL_TO],
    'reply_to' => $email,
    'subject'  => "📋 New Quote: $service — $fullName",
    'html'     => $htmlBody,
    'text'     => $textBody,
];

if (!empty($attachments)) {
    $payload['attachments'] = array_map(
        fn($a) => ['filename' => $a['filename'], 'content' => $a['content']],
        $attachments
    );
}

$ch = curl_init('https://api.resend.com/emails');
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_POST           => true,
    CURLOPT_HTTPHEADER     => [
        'Authorization: Bearer ' . RESEND_API_KEY,
        'Content-Type: application/json',
        'User-Agent: Qantidad/2.0 PHP',
    ],
    CURLOPT_POSTFIELDS     => json_encode($payload, JSON_UNESCAPED_UNICODE),
    CURLOPT_TIMEOUT        => 30,
    CURLOPT_CONNECTTIMEOUT => 10,
    CURLOPT_SSL_VERIFYPEER => true,
    CURLOPT_SSL_VERIFYHOST => 2,
]);

$resBody   = curl_exec($ch);
$httpCode  = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
$curlErr   = curl_error($ch);
curl_close($ch);

if ($curlErr) {
    error_log('[Qantidad] cURL error: ' . $curlErr);
    respond(false, 'Connection to mail service failed. Please email us directly.', 503);
}

$result = json_decode($resBody, true);

if ($httpCode === 200 || $httpCode === 201) {
    respond(true, "Your quote request has been sent successfully. We'll be in touch within 24–48 hours.");
}

$apiErr = $result['message'] ?? ($result['name'] ?? 'Unknown');
error_log("[Qantidad] Resend error HTTP $httpCode: $apiErr");
respond(false, 'Message could not be sent. Please try again or email us directly.', 500);


// ── Helper de respuesta JSON ─────────────────────────────────
function respond(bool $ok, string $message, int $code = 200): never
{
    http_response_code($code);
    echo json_encode(['ok' => $ok, 'message' => $message], JSON_UNESCAPED_UNICODE);
    exit;
}
