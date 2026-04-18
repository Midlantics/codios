import os
from functools import lru_cache


class Settings:
    def __init__(self) -> None:
        self.database_url = os.environ["DATABASE_URL"]
        self.supabase_jwt_secret = os.environ["SUPABASE_JWT_SECRET"]
        self.allowed_origins = os.getenv("ALLOWED_ORIGINS", "*")
        self.codios_private_key = os.getenv("CODIOS_PRIVATE_KEY", "")
        self.codios_public_key  = os.getenv("CODIOS_PUBLIC_KEY", "")
        self.codios_did         = os.getenv("CODIOS_DID", "")
        self.redis_url          = os.getenv("REDIS_URL", "")
        self.app_url            = os.getenv("APP_URL", "http://localhost:8080")
        self.gateway_secret     = os.getenv("GATEWAY_SECRET", "")
        self.vpc_mode           = os.getenv("VPC_MODE", "true").lower() == "true"
        # S3 audit export (optional)
        self.s3_audit_bucket    = os.getenv("S3_AUDIT_BUCKET", "")
        self.aws_access_key_id  = os.getenv("AWS_ACCESS_KEY_ID", "")
        self.aws_secret_key     = os.getenv("AWS_SECRET_ACCESS_KEY", "")
        self.aws_region         = os.getenv("AWS_REGION", "us-east-1")


@lru_cache
def get_settings() -> Settings:
    return Settings()
