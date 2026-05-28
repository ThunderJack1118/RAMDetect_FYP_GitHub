"""
ramdetect.case_management
-------------------------
Case Management and Audit Trail module for RAMDetect.

Public surface
--------------
Use ``initialise_database()`` at application startup, then import the
service functions you need directly from their modules.

Quick start::

    from ramdetect.case_management import initialise_database
    initialise_database()

    from ramdetect.case_management.auth_service   import authenticate_user
    from ramdetect.case_management.case_service   import create_case, list_cases
    from ramdetect.case_management.evidence_service import register_evidence

Design constraints
------------------
  - This module is for case workflow, audit trail, and evidence metadata only.
  - It must NOT modify FeatureMapper, Autoencoder, Random Forest, the fixed
    0.5 threshold, or any verdict logic.
  - All ML classification results are stored as-is from the RF-AE pipeline.
"""

from ramdetect.case_management.init_db import initialise_database

__all__ = [
    "initialise_database",
]
