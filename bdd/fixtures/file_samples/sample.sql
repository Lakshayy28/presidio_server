-- SQL script with embedded PII for sanitizer testing

-- Create customer table
CREATE TABLE customers (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100),
    email VARCHAR(100),
    phone VARCHAR(20),
    ssn VARCHAR(11)
);

-- Insert sample data with PII
INSERT INTO customers (name, email, phone, ssn) VALUES
    ('Alice Johnson', 'alice.johnson@securecorp.com', '+1-555-867-5309', '323-45-6789'),
    ('Bob Williams', 'bob.williams@example.com', '+44-20-7946-0958', '219-09-9999');

-- Database connection for migration
-- postgres://admin:Passw0rd!@db.prod.internal:5432/payments
-- Contact DBA: dba@securecorp.com, phone: +1-555-123-4567
