To use this provider for Sql Server, configure the oiosaml.net sessionType to 
dk.nita.saml20.ext.sessionstore.sqlserver.SqlServerSessionStoreProvider, dk.nita.saml20.ext.sessionstore.sqlserver

The tables must be created in the database beforehand.

This nuget contains a CreateTable.sql script (look in the packages folder where the nuget is extracted) that creates the necessary tables.

Since session state is stored in Sql tables, a maintenance job is required to ensure sessions are clean up. The provider has an internal job that will clear expired records. 

This provider supports the following configurations:
Connection string "oiosaml:SqlServerSessionStoreProvider" (required)
App setting "oiosaml:SqlServerSessionStoreProvider:Schema" (optional, defaults to "dbo")
App setting "oiosaml:SqlServerSessionStoreProvider:CleanupIntervalSeconds" (optional, defaults to 60)
App setting "oiosaml:SqlServerSessionStoreProvider:DisableCleanup" (optional, default to "false")