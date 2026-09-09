export class AppError extends Error {
  /**
   * @param {string} message
   * @param {number} exitCode
   * @param {string} code
   * @param {ErrorOptions} [options]
   */
  constructor(message, exitCode, code, options = {}) {
    super(message, options);
    this.name = 'AppError';
    this.exitCode = exitCode;
    this.code = code;
  }
}

export const EXIT_CODES = Object.freeze({ success: 0, mismatch: 2, invalid: 64, network: 69, internal: 70 });
