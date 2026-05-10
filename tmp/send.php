<?php
/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║         QANTIDAD — Mailer Backend                          ║
 * ║         PHP nativo · mail() · Sin dependencias externas    ║
 * ╠══════════════════════════════════════════════════════════════╣
 * ║  Seguridad implementada:                                    ║
 * ║  · CORS estricto por dominio                               ║
 * ║  · Headers HTTP de seguridad                               ║
 * ║  · Rate limiting por IP (archivo JSON, sin BD)             ║
 * ║  · Honeypot anti-spam                                      ║
 * ║  · Validación de timestamp (evita bots instantáneos)       ║
 * ║  · Sanitización de todos los inputs                        ║
 * ║  · Protección contra header injection en email             ║
 * ║  · Validación MIME real de archivos (libmagic)             ║
 * ║  · Adjuntos via MIME multipart nativo                      ║
 * ║  · Log de errores server-side sin exponer al cliente       ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * INSTALACIÓN EN cPanel
 * ─────────────────────
 * 1. Subir este archivo en public_html/ (junto a index.html)
 * 2. Crear la carpeta public_html/tmp/ con permisos 755
 * 3. Editar el bloque CONFIG más abajo con tus datos reales
 * 4. Verificar que PHP mail() esté activo (cPanel → PHP → phpinfo)
 */

declare(strict_types=1);

// ══════════════════════════════════════════════════════════════
//  ⚙️  CONFIG — EDITA SOLO ESTE BLOQUE
// ══════════════════════════════════════════════════════════════

/** Correo empresarial donde recibirás las solicitudes */
define('MAIL_TO',        'javierflorezwork@gmail.com');

/** Nombre del remitente que aparece en tu bandeja */
define('MAIL_FROM_NAME', 'Qantidad Web');

/**
 * Dirección "From". DEBE pertenecer al mismo dominio de tu hosting.
 * Ej: si tu sitio es qantidad.com.au → usa noreply@qantidad.com.au
 * Usar un dominio externo puede hacer que el email caiga en spam.
 */
define('MAIL_FROM',      'noreply@qantidad.com.au');

/** URL de tu sitio SIN barra final — usada para CORS */
define('SITE_DOMAIN',    'https://qantidad.com.au');

// ── Límites de archivos ──
define('MAX_FILE_BYTES',  10 * 1024 * 1024);  // 10 MB por archivo
define('MAX_TOTAL_BYTES', 35 * 1024 * 1024);  // 35 MB total adjuntos
define('MAX_FILES',       5);                  // Máx. archivos por envío

// ── Rate limiting ──
define('RATE_MAX',    5);                       // Envíos máximos por IP
define('RATE_WINDOW', 3600);                    // Ventana en segundos (1 h)
define('RATE_FILE',   __DIR__ . '/tmp/rl.json'); // Caché (crea carpeta tmp/)

// ── Tipos de archivo permitidos ──
define('ALLOWED_EXTS', ['pdf', 'dwg', 'dxf', 'rvt', 'png', 'jpg', 'jpeg', 'zip']);
define('SAFE_MIMES', [
    'application/pdf',
    'image/jpeg',
    'image/png',
    'application/zip',
    'application/x-zip-compressed',
    'application/octet-stream', // DWG / DXF / RVT usan este MIME en muchos sistemas
]);

// ══════════════════════════════════════════════════════════════


// ────────────────────────────────────────────────────────────
//  1. Headers de seguridad HTTP
// ────────────────────────────────────────────────────────────
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

// CORS estricto: solo tu dominio (+ localhost para desarrollo)
$origin         = $_SERVER['HTTP_ORIGIN'] ?? '';
$allowedOrigins = [SITE_DOMAIN, 'http://localhost', 'http://127.0.0.1'];
if (in_array($origin, $allowedOrigins, true)) {
    header("Access-Control-Allow-Origin: $origin");
} else {
    header('Access-Control-Allow-Origin: ' . SITE_DOMAIN);
}
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, X-Requested-With');

// Preflight CORS
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// Solo método POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    respond(false, 'Method not allowed.', 405);
}

// Solo peticiones AJAX (el JS agrega este header automáticamente)
if (($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '') !== 'XMLHttpRequest') {
    respond(false, 'Invalid request.', 403);
}


// ────────────────────────────────────────────────────────────
//  2. Rate limiting por IP (archivo JSON, sin base de datos)
// ────────────────────────────────────────────────────────────
(function (): void {
    $dir = dirname(RATE_FILE);
    if (!is_dir($dir)) {
        @mkdir($dir, 0755, true);
    }

    // IP real (compatible con Cloudflare y proxies)
    $ip  = $_SERVER['HTTP_CF_CONNECTING_IP']
        ?? $_SERVER['HTTP_X_FORWARDED_FOR']
        ?? $_SERVER['REMOTE_ADDR']
        ?? 'unknown';

    // Guardar solo el hash SHA-256 — nunca la IP en texto claro
    $key = hash('sha256', trim(explode(',', $ip)[0]));
    $now = time();

    $data = [];
    if (file_exists(RATE_FILE)) {
        $raw  = @file_get_contents(RATE_FILE);
        $data = ($raw !== false) ? (json_decode($raw, true) ?? []) : [];
    }

    // Purgar entradas expiradas
    foreach ($data as $k => $v) {
        if ($now - $v['first'] > RATE_WINDOW) {
            unset($data[$k]);
        }
    }

    $data[$key] = $data[$key] ?? ['count' => 0, 'first' => $now];
    $data[$key]['count']++;

    if ($data[$key]['count'] > RATE_MAX) {
        @file_put_contents(RATE_FILE, json_encode($data), LOCK_EX);
        respond(false, 'Too many requests. Please try again in an hour.', 429);
    }

    @file_put_contents(RATE_FILE, json_encode($data), LOCK_EX);
})();


// ────────────────────────────────────────────────────────────
//  3. Anti-spam: honeypot + validación de timestamp
// ────────────────────────────────────────────────────────────

// Honeypot: campo invisible; los bots lo rellenan, los humanos no
if (!empty($_POST['website'])) {
    // Respuesta silenciosa para no revelar la trampa
    respond(true, "Your request has been received. We'll be in touch soon.");
}

// Timestamp: evita bots instantáneos y sesiones expiradas
$ts  = (int)($_POST['_ts'] ?? 0);
$age = time() - $ts;
if ($ts === 0 || $age < 3 || $age > 3600) {
    respond(false, 'Session expired. Please reload the page and try again.', 400);
}


// ────────────────────────────────────────────────────────────
//  4. Sanitizar y validar campos
// ────────────────────────────────────────────────────────────

/** Limpia un valor: quita tags, espacios, escapa HTML */
function sanitize(string $v): string
{
    return htmlspecialchars(strip_tags(trim($v)), ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

$firstName   = sanitize($_POST['first_name']   ?? '');
$lastName    = sanitize($_POST['last_name']    ?? '');
$rawEmail    = trim($_POST['email']            ?? '');
$email       = filter_var($rawEmail, FILTER_VALIDATE_EMAIL);
$phone       = sanitize($_POST['phone']        ?? '');
$service     = sanitize($_POST['service']      ?? '');
$projectType = sanitize($_POST['project_type'] ?? '');
$details     = sanitize($_POST['details']      ?? '');
$formSource  = sanitize($_POST['form_source']  ?? 'Website');

// Validaciones
$errors = [];
if (!$firstName)                               $errors[] = 'First name is required.';
if (!$lastName)                                $errors[] = 'Last name is required.';
if (!$email)                                   $errors[] = 'A valid email address is required.';
if (!$phone)                                   $errors[] = 'Phone number is required.';
if (!$service || str_starts_with($service, 'Select')) {
                                               $errors[] = 'Please select a service.';
}
if (strlen($firstName) > 80)  $errors[] = 'First name is too long.';
if (strlen($lastName)  > 80)  $errors[] = 'Last name is too long.';
if (strlen($phone)     > 30)  $errors[] = 'Phone number is too long.';
if (strlen($details)  > 3000) $errors[] = 'Project details too long (max 3 000 chars).';

if (!empty($errors)) {
    respond(false, implode(' ', $errors), 422);
}

$fullName = "$firstName $lastName";

// Protección contra header injection en el campo email
if (preg_match('/[\r\n\t]/', $rawEmail)) {
    respond(false, 'Invalid email address.', 422);
}


// ────────────────────────────────────────────────────────────
//  5. Procesar y validar archivos adjuntos
// ────────────────────────────────────────────────────────────

/** Obtiene el MIME type real del archivo usando libmagic */
function getRealMime(string $tmpPath): string
{
    if (function_exists('finfo_open')) {
        $fi   = new finfo(FILEINFO_MIME_TYPE);
        $mime = $fi->file($tmpPath);
        return ($mime !== false) ? $mime : 'application/octet-stream';
    }
    // Fallback si finfo no está disponible
    return mime_content_type($tmpPath) ?: 'application/octet-stream';
}

$attachments = []; // [['name'=>string, 'mime'=>string, 'data'=>string], ...]
$totalBytes  = 0;

if (!empty($_FILES['files']['name'][0])) {
    $files = $_FILES['files'];
    $count = count($files['name']);

    if ($count > MAX_FILES) {
        respond(false, 'Maximum ' . MAX_FILES . ' files allowed per submission.', 422);
    }

    for ($i = 0; $i < $count; $i++) {
        if ($files['error'][$i] === UPLOAD_ERR_NO_FILE) continue;

        // Códigos de error de PHP upload
        $uploadErrors = [
            UPLOAD_ERR_INI_SIZE   => 'exceeds server limit',
            UPLOAD_ERR_FORM_SIZE  => 'exceeds form limit',
            UPLOAD_ERR_PARTIAL    => 'was only partially uploaded',
            UPLOAD_ERR_NO_TMP_DIR => 'no temporary folder available',
            UPLOAD_ERR_CANT_WRITE => 'failed to write to disk',
            UPLOAD_ERR_EXTENSION  => 'blocked by a server extension',
        ];

        if ($files['error'][$i] !== UPLOAD_ERR_OK) {
            $reason = $uploadErrors[$files['error'][$i]] ?? 'unknown error';
            respond(false, "File #" . ($i + 1) . " could not be uploaded ($reason). Please try again.", 422);
        }

        // Sanitizar nombre del archivo
        $rawName  = basename($files['name'][$i]);
        $safeName = preg_replace('/[^a-zA-Z0-9._\-]/', '_', $rawName);
        $ext      = strtolower(pathinfo($safeName, PATHINFO_EXTENSION));
        $size     = (int)$files['size'][$i];
        $tmpPath  = $files['tmp_name'][$i];

        // Validar extensión contra whitelist
        if (!in_array($ext, ALLOWED_EXTS, true)) {
            respond(
                false,
                "'$safeName' has an unsupported format. "
                . "Accepted: " . implode(', ', ALLOWED_EXTS),
                422
            );
        }

        // Tamaño individual
        if ($size > MAX_FILE_BYTES) {
            $maxMb = MAX_FILE_BYTES / 1048576;
            respond(false, "'$safeName' exceeds the {$maxMb} MB per-file limit.", 422);
        }

        // Tamaño total acumulado
        $totalBytes += $size;
        if ($totalBytes > MAX_TOTAL_BYTES) {
            $maxT = MAX_TOTAL_BYTES / 1048576;
            respond(false, "Total attachments exceed {$maxT} MB. Please reduce the number of files.", 422);
        }

        // Verificar que sea un upload real de PHP (no path inyectado)
        if (!is_uploaded_file($tmpPath)) {
            respond(false, "Security check failed for '$safeName'.", 422);
        }

        // Validar MIME real para tipos con contenido verificable
        $realMime    = getRealMime($tmpPath);
        $strictTypes = ['pdf', 'jpg', 'jpeg', 'png'];
        if (in_array($ext, $strictTypes, true) && !in_array($realMime, SAFE_MIMES, true)) {
            respond(false, "'$safeName' failed MIME validation. Please upload a valid file.", 422);
        }

        // Leer contenido binario
        $content = file_get_contents($tmpPath);
        if ($content === false) {
            respond(false, "Could not read '$safeName'. Please try again.", 500);
        }

        $attachments[] = [
            'name' => $safeName,
            'mime' => $realMime,
            'data' => $content,
        ];
    }
}

$fileCount = count($attachments);


// ────────────────────────────────────────────────────────────
//  6. Construir el cuerpo HTML del email
// ────────────────────────────────────────────────────────────

$submittedAt = date('D, d M Y \a\t H:i T');

// Sección de archivos adjuntos
if ($fileCount > 0) {
    $items = implode('', array_map(
        fn($a) => "<li style='color:#5a6278;font-size:14px;padding:3px 0;'>📎 " . htmlspecialchars($a['name']) . "</li>",
        $attachments
    ));
    $filesSection = "<strong style='color:#0d1f3c;font-size:14px;'>$fileCount file(s) attached:</strong>"
                  . "<ul style='margin:8px 0 0;padding-left:18px;'>$items</ul>";
} else {
    $filesSection = "<em style='color:#9ca3af;font-size:14px;'>No files attached.</em>";
}

$detailsSection     = $details
    ? "<p style='margin:0;font-size:14px;color:#5a6278;line-height:1.7;'>" . nl2br($details) . "</p>"
    : "<em style='color:#9ca3af;font-size:14px;'>Not provided.</em>";

$projectTypeSection = $projectType ?: '<em style="color:#9ca3af;">Not specified</em>';

$replySubject = rawurlencode("Re: Your Quote Request – $service");
$replyBody    = rawurlencode(
    "Hi $firstName,\n\nThank you for reaching out to Qantidad. We've received your quote request "
    . "and will be in touch within 24–48 hours.\n\nKind regards,\nThe Qantidad Team"
);

$htmlBody = <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>New Quote – Qantidad</title>
</head>
<body style="margin:0;padding:0;background:#f7f8fa;font-family:Arial,Helvetica,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#f7f8fa;padding:32px 16px;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" border="0"
  style="background:#fff;border-radius:16px;overflow:hidden;max-width:600px;width:100%;
         box-shadow:0 4px 32px rgba(0,0,0,0.10);">

  <!-- Header -->
  <tr><td style="background:#0d1f3c;padding:24px 36px;">
    <table width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
      <td>
        <span style="font-size:22px;font-weight:800;color:#fff;letter-spacing:1px;">▲ QANTIDAD</span><br>
        <span style="font-size:11px;color:rgba(255,255,255,0.5);letter-spacing:2px;text-transform:uppercase;">Quantity Estimating</span>
      </td>
      <td align="right" style="vertical-align:middle;">
        <span style="display:inline-block;background:#f07c1c;color:#fff;font-size:11px;font-weight:700;
                     letter-spacing:1.5px;text-transform:uppercase;padding:5px 14px;border-radius:100px;">
          New Quote Request
        </span>
      </td>
    </tr></table>
  </td></tr>

  <!-- Alert bar -->
  <tr><td style="background:#f07c1c;padding:12px 36px;">
    <p style="margin:0;color:#fff;font-size:14px;font-weight:700;">
      📋 &nbsp;New quote request received from {$formSource}
    </p>
  </td></tr>

  <!-- Body -->
  <tr><td style="padding:32px 36px;">

    <p style="margin:0 0 14px;font-size:11px;font-weight:700;color:#f07c1c;letter-spacing:2px;text-transform:uppercase;">Client Information</p>
    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:24px;">
      <tr>
        <td width="50%" style="padding:0 6px 10px 0;vertical-align:top;">
          <div style="background:#f7f8fa;border-radius:10px;padding:13px 15px;">
            <p style="margin:0 0 3px;font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Full Name</p>
            <p style="margin:0;font-size:15px;color:#0d1f3c;font-weight:700;">{$fullName}</p>
          </div>
        </td>
        <td width="50%" style="padding:0 0 10px 6px;vertical-align:top;">
          <div style="background:#f7f8fa;border-radius:10px;padding:13px 15px;">
            <p style="margin:0 0 3px;font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Email</p>
            <p style="margin:0;font-size:14px;color:#0d1f3c;font-weight:700;word-break:break-word;">{$email}</p>
          </div>
        </td>
      </tr>
      <tr>
        <td width="50%" style="padding:0 6px 0 0;vertical-align:top;">
          <div style="background:#f7f8fa;border-radius:10px;padding:13px 15px;">
            <p style="margin:0 0 3px;font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Phone</p>
            <p style="margin:0;font-size:15px;color:#0d1f3c;font-weight:700;">{$phone}</p>
          </div>
        </td>
        <td width="50%" style="padding:0 0 0 6px;vertical-align:top;">
          <div style="background:#f7f8fa;border-radius:10px;padding:13px 15px;">
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
          <div style="background:#f7f8fa;border-radius:10px;padding:13px 15px;">
            <p style="margin:0 0 3px;font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Service</p>
            <p style="margin:0;font-size:15px;color:#0d1f3c;font-weight:700;">{$service}</p>
          </div>
        </td>
        <td width="50%" style="padding:0 0 10px 6px;vertical-align:top;">
          <div style="background:#f7f8fa;border-radius:10px;padding:13px 15px;">
            <p style="margin:0 0 3px;font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Project Type</p>
            <p style="margin:0;font-size:15px;color:#0d1f3c;font-weight:700;">{$projectTypeSection}</p>
          </div>
        </td>
      </tr>
    </table>

    <div style="background:#f7f8fa;border-radius:10px;padding:14px 16px;margin-bottom:24px;">
      <p style="margin:0 0 6px;font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Project Notes</p>
      {$detailsSection}
    </div>

    <p style="margin:0 0 14px;font-size:11px;font-weight:700;color:#f07c1c;letter-spacing:2px;text-transform:uppercase;">Attachments</p>
    <div style="background:#f7f8fa;border-radius:10px;padding:14px 16px;margin-bottom:28px;">{$filesSection}</div>

    <table width="100%" cellpadding="0" cellspacing="0" border="0">
      <tr><td style="background:#0d1f3c;border-radius:10px;padding:18px 22px;">
        <p style="margin:0 0 12px;font-size:13px;color:rgba(255,255,255,0.7);">Reply directly to this client:</p>
        <a href="mailto:{$email}?subject={$replySubject}&body={$replyBody}"
           style="display:inline-block;background:#f07c1c;color:#fff;font-weight:700;font-size:14px;
                  padding:12px 24px;border-radius:8px;text-decoration:none;">
          ✉ Reply to {$firstName} →
        </a>
      </td></tr>
    </table>

  </td></tr>

  <!-- Footer -->
  <tr><td style="background:#f7f8fa;border-top:1px solid #eef0f4;padding:16px 36px;text-align:center;">
    <p style="margin:0;font-size:12px;color:#9ca3af;">
      Automated notification from <strong>qantidad.com.au</strong> &middot; Do not reply to this address
    </p>
  </td></tr>

</table>
</td></tr>
</table>
</body>
</html>
HTML;

// Texto plano alternativo
$textBody = "NEW QUOTE REQUEST — QANTIDAD\n"
    . str_repeat('=', 48) . "\n\n"
    . "Source:    $formSource\n"
    . "Date:      $submittedAt\n\n"
    . "CLIENT\n" . str_repeat('-', 24) . "\n"
    . "Name:      $fullName\n"
    . "Email:     $email\n"
    . "Phone:     $phone\n\n"
    . "PROJECT\n" . str_repeat('-', 24) . "\n"
    . "Service:   $service\n"
    . "Type:      " . ($projectType ?: 'Not specified') . "\n"
    . "Notes:     " . ($details ?: 'Not provided') . "\n\n"
    . "FILES\n" . str_repeat('-', 24) . "\n"
    . ($fileCount > 0
        ? implode("\n", array_map(fn($a) => "  · " . $a['name'], $attachments))
        : "  None attached") . "\n\n"
    . str_repeat('=', 48) . "\n"
    . "Reply to: $email\n";


// ────────────────────────────────────────────────────────────
//  7. Construir el email MIME multipart (PHP mail() nativo)
// ────────────────────────────────────────────────────────────

/** Genera un boundary MIME único y criptográficamente seguro */
function boundary(): string
{
    return '----=_QBoundary_' . bin2hex(random_bytes(16));
}

$outerBoundary = boundary();
$altBoundary   = boundary();

// Asunto con UTF-8 codificado
$subject = '=?UTF-8?B?' . base64_encode("New Quote: $service — $fullName") . '?=';

// Headers base
$fromEncoded  = '=?UTF-8?B?' . base64_encode(MAIL_FROM_NAME) . '?=';
$headers      = "From: $fromEncoded <" . MAIL_FROM . ">\r\n";
$headers     .= "Reply-To: =?UTF-8?B?" . base64_encode($fullName) . "?= <$email>\r\n";
$headers     .= "MIME-Version: 1.0\r\n";
$headers     .= "X-Mailer: Qantidad-Mailer/2.0 PHP\r\n";
$headers     .= "X-Priority: 1 (Highest)\r\n";
$headers     .= "Importance: High\r\n";

if ($fileCount > 0) {
    // Con adjuntos: multipart/mixed → dentro, multipart/alternative
    $headers .= "Content-Type: multipart/mixed; boundary=\"$outerBoundary\"\r\n";

    $body  = "This is a multi-part message in MIME format.\r\n\r\n";

    // Parte alternativa (texto + HTML)
    $body .= "--$outerBoundary\r\n";
    $body .= "Content-Type: multipart/alternative; boundary=\"$altBoundary\"\r\n\r\n";

    $body .= "--$altBoundary\r\n";
    $body .= "Content-Type: text/plain; charset=UTF-8\r\n";
    $body .= "Content-Transfer-Encoding: quoted-printable\r\n\r\n";
    $body .= quoted_printable_encode($textBody) . "\r\n";

    $body .= "--$altBoundary\r\n";
    $body .= "Content-Type: text/html; charset=UTF-8\r\n";
    $body .= "Content-Transfer-Encoding: quoted-printable\r\n\r\n";
    $body .= quoted_printable_encode($htmlBody) . "\r\n";

    $body .= "--$altBoundary--\r\n\r\n";

    // Archivos adjuntos
    foreach ($attachments as $att) {
        $encoded  = chunk_split(base64_encode($att['data']));
        $safeName = $att['name'];

        $body .= "--$outerBoundary\r\n";
        $body .= "Content-Type: " . $att['mime'] . "; name=\"$safeName\"\r\n";
        $body .= "Content-Transfer-Encoding: base64\r\n";
        $body .= "Content-Disposition: attachment; filename=\"$safeName\"\r\n\r\n";
        $body .= $encoded . "\r\n";
    }

    $body .= "--$outerBoundary--\r\n";

} else {
    // Sin adjuntos: solo multipart/alternative
    $headers .= "Content-Type: multipart/alternative; boundary=\"$altBoundary\"\r\n";

    $body  = "--$altBoundary\r\n";
    $body .= "Content-Type: text/plain; charset=UTF-8\r\n";
    $body .= "Content-Transfer-Encoding: quoted-printable\r\n\r\n";
    $body .= quoted_printable_encode($textBody) . "\r\n";

    $body .= "--$altBoundary\r\n";
    $body .= "Content-Type: text/html; charset=UTF-8\r\n";
    $body .= "Content-Transfer-Encoding: quoted-printable\r\n\r\n";
    $body .= quoted_printable_encode($htmlBody) . "\r\n";

    $body .= "--$altBoundary--\r\n";
}


// ────────────────────────────────────────────────────────────
//  8. Enviar el email
// ────────────────────────────────────────────────────────────

// Parámetro -f evita que algunos servidores marquen el email como spam
$extraParams = '-f ' . escapeshellarg(MAIL_FROM);

$sent = @mail(MAIL_TO, $subject, $body, $headers, $extraParams);

if ($sent) {
    respond(true, "Your quote request has been sent successfully. We'll be in touch within 24–48 hours.");
} else {
    // Registrar error en el log del servidor (invisible para el cliente)
    error_log(
        sprintf(
            '[Qantidad] mail() FAILED | from=%s <%s> | service=%s | files=%d | %s',
            $fullName, $email, $service, $fileCount, date('Y-m-d H:i:s')
        )
    );
    respond(
        false,
        'Your message could not be sent. Please try again or email us directly at ' . MAIL_TO,
        500
    );
}


// ────────────────────────────────────────────────────────────
//  Helper: respuesta JSON unificada
// ────────────────────────────────────────────────────────────

/**
 * Emite una respuesta JSON y termina la ejecución.
 *
 * @param bool   $ok      true = éxito, false = error
 * @param string $message Mensaje para el usuario
 * @param int    $code    Código HTTP
 */
function respond(bool $ok, string $message, int $code = 200): never
{
    http_response_code($code);
    echo json_encode(
        ['ok' => $ok, 'message' => $message],
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
    );
    exit;
}
