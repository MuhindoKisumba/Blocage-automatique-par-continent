/* =====================================================
    BLOCAGE AUTOMATIQUE PAR CONTINENT
===================================================== */

-------------------------------------------------------
-- 1 Table continents autorisés
-------------------------------------------------------

CREATE TABLE IF NOT EXISTS allowed_continents (
    continent_code TEXT PRIMARY KEY,
    continent_name TEXT
);

-- Exemple : autoriser uniquement Afrique
INSERT INTO allowed_continents VALUES
('AF','Africa')
ON CONFLICT DO NOTHING;

-------------------------------------------------------
-- 2 Fonction récupérer continent depuis IP
-------------------------------------------------------

CREATE OR REPLACE FUNCTION get_continent_from_ip(ip TEXT)
RETURNS TEXT AS $$
DECLARE
    result JSON;
    continent TEXT;
BEGIN

    IF ip IS NULL THEN
        RETURN 'UNKNOWN';
    END IF;

    result := maxmind_lookup(
        '/usr/share/GeoIP/GeoLite2-Country.mmdb',
        ip
    );

    continent := result->'continent'->>'code';

    IF continent IS NULL THEN
        RETURN 'UNKNOWN';
    END IF;

    RETURN continent;

END;
$$ LANGUAGE plpgsql;

-------------------------------------------------------
-- 3 Vérifier si continent autorisé
-------------------------------------------------------

CREATE OR REPLACE FUNCTION is_continent_allowed(cont TEXT)
RETURNS BOOLEAN AS $$
DECLARE
    allowed BOOLEAN;
BEGIN

    SELECT EXISTS(
        SELECT 1
        FROM allowed_continents
        WHERE continent_code = cont
    ) INTO allowed;

    RETURN allowed;

END;
$$ LANGUAGE plpgsql;

-------------------------------------------------------
-- 4 Sécurité par continent
-------------------------------------------------------

CREATE OR REPLACE FUNCTION geo_continent_security()
RETURNS TRIGGER AS $$
DECLARE
    ip TEXT;
    cont TEXT;
BEGIN

    ip := NEW.client_addr;

    IF ip IS NULL THEN
        RETURN NEW;
    END IF;

    cont := get_continent_from_ip(ip);

    IF NOT is_continent_allowed(cont) THEN

        -- journaliser
        INSERT INTO audit_log(username, action, table_name, query, client_addr)
        VALUES (
            NEW.username,
            'CONTINENT_BLOCK',
            'SECURITY',
            'Connexion depuis continent non autorise : ' || cont,
            ip
        );

        -- blocage firewall global
        PERFORM block_ip_everywhere(
            ip,
            'Continent non autorise : ' || cont
        );

    END IF;

    RETURN NEW;

END;
$$ LANGUAGE plpgsql;

-------------------------------------------------------
-- 5 Trigger surveillance
-------------------------------------------------------

DROP TRIGGER IF EXISTS geo_continent_monitor ON audit_log;

CREATE TRIGGER geo_continent_monitor
AFTER INSERT ON audit_log
FOR EACH ROW
EXECUTE FUNCTION geo_continent_security();

-------------------------------------------------------
-- 6 Vue monitoring
-------------------------------------------------------

CREATE OR REPLACE VIEW blocked_continent_activity AS
SELECT
    username,
    client_addr,
    query,
    date_action
FROM audit_log
WHERE action = 'CONTINENT_BLOCK'
ORDER BY date_action DESC;

-------------------------------------------------------
-- 7 Vérification
-------------------------------------------------------

-- Voir les blocages
-- SELECT * FROM blocked_continent_activity;

-- Voir continents autorisés
-- SELECT * FROM allowed_continents;
