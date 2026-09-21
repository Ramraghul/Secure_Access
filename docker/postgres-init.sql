-- Runs once when the Docker volume is first created.
-- The integration tests use their own database so they never touch development data.
CREATE DATABASE secureaccess_test;
