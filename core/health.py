"""Health check and status monitoring for production deployments."""
import time
from datetime import datetime
from typing import Dict, Any

from .config import config
from .database import get_session
from .db import Session
from .logging_config import get_logger
from .rate_limiter import get_resource_monitor

logger = get_logger("health")


class HealthCheck:
    """System health check and status reporting."""

    @staticmethod
    def check_database() -> Dict[str, Any]:
        """Check database connectivity and health."""
        try:
            start = time.time()
            with get_session() as db:
                # Simple query to test connection
                db.query(Session).first()
            
            duration = time.time() - start
            return {
                "status": "healthy",
                "response_time_ms": round(duration * 1000, 2),
                "database_url": config.database_url.split("@")[-1] if "@" in config.database_url else "sqlite"
            }
        except Exception as e:
            logger.error(f"Database health check failed: {str(e)}", exc_info=True)
            return {
                "status": "unhealthy",
                "error": str(e)
            }

    @staticmethod
    def check_ollama() -> Dict[str, Any]:
        """Check Ollama service availability."""
        try:
            import requests
            
            start = time.time()
            response = requests.get(f"{config.ollama_host}/api/tags", timeout=5)
            duration = time.time() - start
            
            if response.status_code == 200:
                return {
                    "status": "healthy",
                    "response_time_ms": round(duration * 1000, 2),
                    "host": config.ollama_host
                }
            else:
                return {
                    "status": "degraded",
                    "http_status": response.status_code,
                    "host": config.ollama_host
                }
        except ImportError:
            return {
                "status": "unknown",
                "error": "requests library not available"
            }
        except Exception as e:
            logger.warning(f"Ollama health check failed: {str(e)}")
            return {
                "status": "unhealthy",
                "error": str(e),
                "host": config.ollama_host
            }

    @staticmethod
    def check_disk_space() -> Dict[str, Any]:
        """Check available disk space."""
        try:
            import shutil
            
            data_dir = config.exports_dir.parent
            usage = shutil.disk_usage(data_dir)
            
            free_gb = usage.free / (1024 ** 3)
            total_gb = usage.total / (1024 ** 3)
            percent_used = (usage.used / usage.total) * 100
            
            status = "healthy"
            if percent_used > 90:
                status = "critical"
            elif percent_used > 80:
                status = "warning"
            
            return {
                "status": status,
                "free_gb": round(free_gb, 2),
                "total_gb": round(total_gb, 2),
                "percent_used": round(percent_used, 2)
            }
        except Exception as e:
            logger.error(f"Disk space check failed: {str(e)}", exc_info=True)
            return {
                "status": "unknown",
                "error": str(e)
            }

    @staticmethod
    def get_active_scans() -> Dict[str, Any]:
        """Get information about active scans."""
        try:
            monitor = get_resource_monitor()
            active = monitor.get_active_scans()
            
            return {
                "count": len(active),
                "scans": [
                    {
                        "session_id": session_id,
                        "duration_seconds": round(duration, 2)
                    }
                    for session_id, duration in active
                ]
            }
        except Exception as e:
            logger.error(f"Active scans check failed: {str(e)}", exc_info=True)
            return {
                "count": 0,
                "error": str(e)
            }

    @staticmethod
    def get_system_info() -> Dict[str, Any]:
        """Get system information."""
        return {
            "environment": config.env,
            "version": "0.1.0",
            "python_version": __import__("sys").version.split()[0],
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

    @classmethod
    def full_health_check(cls) -> Dict[str, Any]:
        """Perform comprehensive health check."""
        logger.debug("Performing full health check")
        
        database = cls.check_database()
        ollama = cls.check_ollama()
        disk = cls.check_disk_space()
        scans = cls.get_active_scans()
        system = cls.get_system_info()
        
        # Determine overall status
        statuses = [database["status"], disk["status"]]
        if "unhealthy" in statuses or "critical" in statuses:
            overall_status = "unhealthy"
        elif "degraded" in statuses or "warning" in statuses:
            overall_status = "degraded"
        else:
            overall_status = "healthy"
        
        return {
            "status": overall_status,
            "timestamp": system["timestamp"],
            "checks": {
                "database": database,
                "ollama": ollama,
                "disk": disk,
                "active_scans": scans
            },
            "system": system
        }

    @classmethod
    def readiness_check(cls) -> bool:
        """Check if system is ready to accept requests."""
        try:
            database = cls.check_database()
            return database["status"] == "healthy"
        except Exception:
            return False

    @classmethod
    def liveness_check(cls) -> bool:
        """Check if system is alive (basic functionality)."""
        try:
            # Just check if we can import core modules
            from . import database, config
            return True
        except Exception:
            return False


def get_health_status() -> Dict[str, Any]:
    """Get current health status (convenience function)."""
    return HealthCheck.full_health_check()
