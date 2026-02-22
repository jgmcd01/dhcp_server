-- Normalize ownership and privileges for application role.

DO $$
DECLARE
  r RECORD;
BEGIN
  FOR r IN
    SELECT tablename
    FROM pg_tables
    WHERE schemaname = 'public'
      AND tablename IN (
        'dhcp_leases', 'lease_event_log', 'dhcp_subnets',
        'dhcp_pools', 'app_users', 'dhcp_server_status'
      )
  LOOP
    EXECUTE format('ALTER TABLE public.%I OWNER TO dhcp', r.tablename);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON public.%I TO dhcp', r.tablename);
  END LOOP;

  FOR r IN
    SELECT sequence_name
    FROM information_schema.sequences
    WHERE sequence_schema = 'public'
      AND sequence_name IN (
        'dhcp_leases_lease_id_seq',
        'lease_event_log_event_id_seq',
        'dhcp_subnets_subnet_id_seq',
        'dhcp_pools_pool_id_seq',
        'app_users_user_id_seq'
      )
  LOOP
    EXECUTE format('ALTER SEQUENCE public.%I OWNER TO dhcp', r.sequence_name);
    EXECUTE format('GRANT USAGE, SELECT, UPDATE ON SEQUENCE public.%I TO dhcp', r.sequence_name);
  END LOOP;
END
$$;
