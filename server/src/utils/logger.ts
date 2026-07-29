import { createLogger, format, transports } from "winston";
import Config from "../config";
import { minimizeFncpLogInfo } from "../auth/fncp-log-boundary";

const devMode = Config.isDevMode;
// See https://github.com/winstonjs/winston#logging-levels
const logLevel = Config.logLevel || "warn";
const logToFile = Config.logToFile;
const fncpLogBoundaryFormat = format((info) => minimizeFncpLogInfo(info))();
const baseFormat = format.combine(
  fncpLogBoundaryFormat,
  format.timestamp(),
  format.errors({ stack: true }),
  format.json()
);

// Console transport:
// - In dev, emit colorful, human-readable logs
// - In prod, emit structured JSON logs
const consoleTransport = new transports.Console({
  format: devMode
    ? format.combine(format.colorize(), format.simple())
    : format.combine(
        format.uncolorize(),
        format.timestamp(),
        format.errors({ stack: true }),
        format.json()
      ),
  level: logLevel,
});

const logger = createLogger({
  level: logLevel,
  exitOnError: false,
  // Base formatter (transport may override). Keep JSON capability always available.
  format: baseFormat,
  defaultMeta: { service: "server" },
  // Write only to console by default, unless the logToFile config is set.
  transports: [consoleTransport],
});

if (logToFile) {
  logger.configure({
    //
    // - Write all logs with importance level of `error` or less to `error.log`
    // - Write all logs with importance level of `info` or less to `combined.log`
    //
    format: baseFormat,
    transports: [
      new transports.File({
        filename: "./logs/error.log",
        level: "error",
      }),
      new transports.File({
        filename: "./logs/combined.log",
      }),
      // Additionally, write all logs to the console as above.
      consoleTransport,
    ],
    exceptionHandlers: [
      new transports.File({ filename: "./logs/exceptions.log" }),
    ],
    rejectionHandlers: [
      new transports.File({ filename: "./logs/rejections.log" }),
    ],
  });
}

export default logger;
