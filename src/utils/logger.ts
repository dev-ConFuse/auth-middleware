import winston from 'winston';
import path from 'path';
import fs from 'fs';
import { AsyncLocalStorage } from 'async_hooks';

// Ensure logs directory exists (file logging is disabled if the FS is read-only)
const logDir = 'logs';
let fileLoggingEnabled = false;

try {
    if (!fs.existsSync(logDir)) {
        fs.mkdirSync(logDir);
    }
    fileLoggingEnabled = true;
} catch (error) {
    // If we can't create the logs directory, disable file logging
    console.warn('Cannot create logs directory, file logging disabled');
}

// Async local storage for correlation ID
export const asyncLocalStorage = new AsyncLocalStorage<Map<string, string>>();

const levels = {
    error: 0,
    warn: 1,
    info: 2,
    http: 3,
    debug: 4,
};

const colors = {
    error: 'red',
    warn: 'yellow',
    info: 'green',
    http: 'magenta',
    debug: 'white',
};

winston.addColors(colors);

// Custom format to inject correlation ID
const addCorrelationId = winston.format((info) => {
    const store = asyncLocalStorage.getStore();
    if (store) {
        const correlationId = store.get('correlationId');
        if (correlationId) {
            info.correlationId = correlationId;
        }
    }
    return info;
});

const format = winston.format.combine(
    addCorrelationId(),
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss:ms' }),
    winston.format.colorize({ all: true }),
    winston.format.printf(
        (info: Record<string, unknown>) => {
            const corr = info.correlationId ? `[${String(info.correlationId)}] ` : '';
            const meta = { ...info };
            delete meta['timestamp'];
            delete meta['level'];
            delete meta['message'];
            delete meta['correlationId'];
            
            let metaStr = '';
            if (Object.keys(meta).length > 0) {
                metaStr = ' ' + JSON.stringify(meta, (key, value) => {
                    if (value instanceof Error) {
                        return { message: value.message, stack: value.stack, name: value.name };
                    }
                    return value;
                });
            }
            return `${String(info['timestamp'])} ${String(info['level'])}: ${corr}${String(info['message'])}${metaStr}`;
        }
    )
);

const transports: winston.transport[] = [
    new winston.transports.Console({
        format, // Use colorized format for console
    }),
];

// Only add file transports if file logging is enabled
if (fileLoggingEnabled) {
    transports.push(
        new winston.transports.File({
            filename: path.join(logDir, 'error.log'),
            level: 'error',
            format: winston.format.combine(
                addCorrelationId(),
                winston.format.uncolorize(),
                winston.format.json()
            ),
            maxsize: 5242880, // 5MB
            maxFiles: 5,
        }),
        new winston.transports.File({
            filename: path.join(logDir, 'app.log'),
            format: winston.format.combine(
                addCorrelationId(),
                winston.format.uncolorize(),
                winston.format.json()
            ),
            maxsize: 10485760, // 10MB
            maxFiles: 5,
        })
    );
}

export const logger = winston.createLogger({
    level: process.env.NODE_ENV === 'development' ? 'debug' : 'info',
    levels,
    transports,
});
