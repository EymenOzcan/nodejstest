const { format, createLogger, transports } = require("winston");

const { LOG_LEVEL } = require("../../config");

const formats = format.combine(
  format.timestamp({ format: "YYYY-MM-DD HH:mm:ss:SSSS" }),
  format.simple(),
  format.splat(),
  format.printf(
    (info) =>
      `${info.timestamp} ${info.level.toUpperCase()}: [email:${
        info.message.email
      }] [location: ${info.message.location} [procType: ${
        info.message.proc_type
      }] [log: ${info.message.log}]]`
  )
);

//* [2025-05-04 12:12:12] INFO : [email:****] [location:****] [procType:****] [log(****)]

const logger = createLogger({
  level: LOG_LEVEL,
  transports: [new transports.Console({ format: formats })],
});

module.exports = logger;
