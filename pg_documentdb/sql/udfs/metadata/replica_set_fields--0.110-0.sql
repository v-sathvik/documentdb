/* Returns replica set fields for isMaster/hello response */

CREATE OR REPLACE FUNCTION __API_SCHEMA_V2__.get_replica_set_fields()
RETURNS __CORE_SCHEMA__.bson
STABLE
LANGUAGE c
AS 'MODULE_PATHNAME', $function$get_replica_set_fields$function$;

COMMENT ON FUNCTION __API_SCHEMA_V2__.get_replica_set_fields()
	IS 'Returns replica set information as single BSON document.';
