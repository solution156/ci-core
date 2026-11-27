"""Keep operational Trivy settings without inheriting policy overrides."""
import os


def scanner_env():
    operational = {'TRIVY_DB_REPOSITORY', 'TRIVY_JAVA_DB_REPOSITORY', 'TRIVY_CHECKS_BUNDLE_REPOSITORY',
                   'TRIVY_CACHE_DIR', 'TRIVY_TIMEOUT', 'TRIVY_NO_PROGRESS', 'TRIVY_SKIP_VERSION_CHECK'}
    return {key: value for key, value in os.environ.items()
            if not key.startswith('TRIVY_') or key in operational}