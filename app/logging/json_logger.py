import json
import logging
import os
from datetime import datetime


class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "message": record.getMessage(),
        }
        event = getattr(record, "event", None)
        if isinstance(event, dict):
            payload.update(event)
        return json.dumps(payload, ensure_ascii=True)


def configure_json_logger(log_dir, logger_name="fleuris"):
    os.makedirs(log_dir, exist_ok=True)
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    log_path = os.path.join(log_dir, "app.json.log")
    handler = logging.FileHandler(log_path)
    handler.setFormatter(JsonFormatter())
    handler.setLevel(logging.INFO)

    if not any(isinstance(existing, logging.FileHandler) for existing in logger.handlers):
        logger.addHandler(handler)

    return logger
