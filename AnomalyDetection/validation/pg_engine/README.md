# Product SQL integration check

The owner installation uses Python 3.10+ and the existing psycopg 3. No Node or ML package is needed for the product.

For this synthetic developer check, run npm ci in this folder and make psycopg 3 available. From the project root, include AnomalyDetection and AnomalyDetection/validation/pg_engine on PYTHONPATH and run:

    python AnomalyDetection/validation/pg_engine/check_product.py

The supplied schema reference is synthetic structure, not owner data. The program creates isolated source tables, then runs the real native product SQL, worker loop and local HTTP routes. It checks late evidence with unchanged semantic revision, old targets, dependent invalidation, feedback, transaction rollback and owned lifecycle.

PGlite uses PostgreSQL 18.6/WASM over pipes. transport.py substitutes the database name and emulates virtual roles/connections, COPY and executemany. Authentication, wire/pipeline/COPY performance, concurrent sessions, Windows process locks, server durability and capacity are NOT evaluated. No real Viewer connection is opened. Output: validation/PRODUCT_engine_contract.json.
