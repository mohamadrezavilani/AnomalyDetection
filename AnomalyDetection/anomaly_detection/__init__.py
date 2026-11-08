"""Independent PostgreSQL consumer; delegates selected pinned Viewer read models."""

BUILD_ID = "AD-20261108-WINSTART"
CONTRACT = "AD-SNAPSHOT-v1"
SOURCE_SHA = "84e9dcc984092735dd4785a26b5af02019eda63d0d5d7ee221bb0c84da37e993"
CATALOG_SHA = "1989cf2ed1dbcd7202f76dcfb8f9530ceadef4331ba01ee55bc0e31f88b36fb6"
SEMANTIC_SCHEMA = "p24-semantic-index-2"
FIVE_NS = 300_000_000_000
KINDS = frozenset({"service_execution", "product_reservation_execution",
                   "wallet_funding_execution", "user_management_execution"})
