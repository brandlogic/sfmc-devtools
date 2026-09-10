import fs from 'node:fs';

const sensitiveKey =
    /^(?:authorization|proxy-authorization|cookie|set-cookie|client_?secret|access_?token|refresh_?token|password|fueloauth)$/i;

/**
 * Validate remote URLs before passing them to Git (including noninteractive init).
 *
 * @param {string} value remote URL
 * @returns {boolean} whether this is an HTTPS or SSH remote
 */
export function isSafeGitRemote(value) {
    if (
        typeof value !== 'string' ||
        /\s/.test(value) ||
        [...value].some((char) => char.codePointAt(0) < 32)
    ) {
        return false;
    }
    if (/^[\w.-]+@[\w.-]+:[\w./-]+$/.test(value)) {
        return true;
    }
    try {
        const url = new URL(value);
        return (
            ['https:', 'ssh:'].includes(url.protocol) &&
            Boolean(url.hostname) &&
            url.pathname.length > 1 &&
            !url.password
        );
    } catch {
        return false;
    }
}

/**
 * Redact authentication fields in API diagnostics without changing the request.
 * Arbitrary business data in bodies is not anonymized.
 *
 * @param {any} value diagnostic data
 * @returns {any} redacted copy
 */
export function redactSecrets(value) {
    if (typeof value === 'string') {
        try {
            const parsed = JSON.parse(value);
            if (parsed && typeof parsed === 'object') {
                return JSON.stringify(redactSecrets(parsed));
            }
        } catch {
            // XML, form data and plain text are handled below.
        }
        return value
            .replaceAll(
                /(<(?:[\w.-]+:)?(?:fueloauth|client_secret|access_token|refresh_token|password)\b[^>]*>)[\s\S]*?(<\/(?:[\w.-]+:)?(?:fueloauth|client_secret|access_token|refresh_token|password)\s*>)/gi,
                '$1[REDACTED]$2'
            )
            .replaceAll(/\bBearer\s+[\w.+/~=-]+/gi, 'Bearer [REDACTED]')
            .replaceAll(
                /((?:^|[?&\s])(?:client_secret|access_token|refresh_token|password)=)[^&\s]*/gi,
                '$1[REDACTED]'
            );
    }
    if (Array.isArray(value)) {
        return value.map(redactSecrets);
    }
    if (value && typeof value === 'object') {
        return Object.fromEntries(
            Object.entries(value).map(([key, child]) => [
                key,
                sensitiveKey.test(key) ? '[REDACTED]' : redactSecrets(child),
            ])
        );
    }
    return value;
}

/**
 * Restrict an existing credentials/session file to its owner on POSIX systems.
 *
 * @param {string} filename credentials file
 * @returns {void} -
 */
export function protectCredentialFile(filename) {
    try {
        const stat = fs.lstatSync(filename);
        if (!stat.isFile() || stat.isSymbolicLink()) {
            throw new Error('Credential storage must be a regular file.');
        }
        if (process.platform !== 'win32') {
            fs.chmodSync(filename, 0o600);
        }
    } catch (ex) {
        if (ex.code !== 'ENOENT') {
            throw ex;
        }
    }
}

/**
 * Write credentials with restrictive permissions from the moment of creation.
 *
 * @param {string} filename credentials file
 * @param {object} content credential data
 * @returns {Promise.<void>} -
 */
export async function writeCredentials(filename, content) {
    protectCredentialFile(filename);
    const flags = fs.constants.O_WRONLY | fs.constants.O_CREAT | (fs.constants.O_NOFOLLOW || 0);
    const handle = await fs.promises.open(filename, flags, 0o600);
    try {
        await handle.chmod(0o600);
        await handle.truncate(0);
        await handle.writeFile(JSON.stringify(content, null, 4) + '\n', 'utf8');
    } finally {
        await handle.close();
    }
}
