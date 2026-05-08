export type ErrorCode =
  | 'BAD_REQUEST'
  | 'UNAUTHORIZED'
  | 'FORBIDDEN'
  | 'NOT_FOUND'
  | 'VALIDATION_ERROR'
  | 'ENCRYPT_GRPC_ERROR'
  | 'SOLANA_RPC_ERROR'
  | 'CACHE_ERROR'
  | 'NEK_ERROR'
  | 'CIPHERTEXT_ERROR'
  | 'GRAPH_ERROR'
  | 'DECRYPT_ERROR'
  | 'INTERNAL_ERROR';

export class AppError extends Error {
  code: ErrorCode;
  status: number;
  details?: unknown;

  constructor(code: ErrorCode, message: string, status = 500, details?: unknown) {
    super(message);
    this.name = 'AppError';
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

export const Errors = {
  badRequest: (message: string, details?: unknown) =>
    new AppError('BAD_REQUEST', message, 400, details),
  unauthorized: (message = 'Unauthorized') => new AppError('UNAUTHORIZED', message, 401),
  forbidden: (message = 'Forbidden') => new AppError('FORBIDDEN', message, 403),
  notFound: (message = 'Not found') => new AppError('NOT_FOUND', message, 404),
  validation: (message: string, details?: unknown) =>
    new AppError('VALIDATION_ERROR', message, 422, details),
  encryptGrpc: (message: string, details?: unknown) =>
    new AppError('ENCRYPT_GRPC_ERROR', message, 502, details),
  solanaRpc: (message: string, details?: unknown) =>
    new AppError('SOLANA_RPC_ERROR', message, 502, details),
  cache: (message: string, details?: unknown) => new AppError('CACHE_ERROR', message, 500, details),
  nek: (message: string, details?: unknown) => new AppError('NEK_ERROR', message, 500, details),
  ciphertext: (message: string, details?: unknown) =>
    new AppError('CIPHERTEXT_ERROR', message, 500, details),
  graph: (message: string, details?: unknown) => new AppError('GRAPH_ERROR', message, 500, details),
  decrypt: (message: string, details?: unknown) =>
    new AppError('DECRYPT_ERROR', message, 500, details),
  internal: (message: string, details?: unknown) =>
    new AppError('INTERNAL_ERROR', message, 500, details),
};

export function toApiError(err: unknown): {
  status: number;
  body: { error: { code: ErrorCode; message: string; details?: unknown } };
} {
  if (err instanceof AppError) {
    return {
      status: err.status,
      body: {
        error: {
          code: err.code,
          message: err.message,
          ...(process.env.NODE_ENV !== 'production' && err.details !== undefined
            ? { details: err.details }
            : {}),
        },
      },
    };
  }
  return {
    status: 500,
    body: {
      error: {
        code: 'INTERNAL_ERROR',
        message: process.env.NODE_ENV === 'production' ? 'Internal server error' : err instanceof Error ? err.message : 'Unknown error',
      },
    },
  };
}
