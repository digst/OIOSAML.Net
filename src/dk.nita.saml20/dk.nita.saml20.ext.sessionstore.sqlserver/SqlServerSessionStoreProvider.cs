using System;
using System.Configuration;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Threading;
using dk.nita.saml20.Session;
using Trace = dk.nita.saml20.Utils.Trace;

namespace dk.nita.saml20.ext.sessionstore.sqlserver
{
    /// <summary>
    /// <see cref="ISessionStoreProvider"/> based on Sql Server.
    /// </summary>
    public class SqlServerSessionStoreProvider : ISessionStoreProvider
    {
        private readonly string _connectionString;
        private readonly string _schema;
        private TimeSpan _sessionTimeout;
        private readonly Timer _cleanupTimer;
        private readonly TimeSpan _cleanupInterval = TimeSpan.FromSeconds(30);
        private ISessionValueFactory _sessionValueFactory;

        /// <summary>
        /// Default constructor that loads settings from configuration file
        /// </summary>
        public SqlServerSessionStoreProvider()
        {
            _connectionString = ConfigurationManager.ConnectionStrings["oiosaml:SqlServerSessionStoreProvider"]?.ConnectionString ?? throw new InvalidOperationException("The connectionstring \'oiosaml:SqlServerSessionStoreProvider\' must be set when using the SqlServerSessionStoreProvider");
            _schema = ConfigurationManager.AppSettings["oiosaml:SqlServerSessionStoreProvider:Schema"] ?? "dbo";

            int cleanupIntervalSeconds;
            if (int.TryParse(ConfigurationManager.AppSettings["oiosaml:SqlServerSessionStoreProvider:CleanupIntervalSeconds"], out cleanupIntervalSeconds))
            {
                _cleanupInterval = TimeSpan.FromSeconds(cleanupIntervalSeconds);
            }

            bool disableCleanup;
            if (!(bool.TryParse(ConfigurationManager.AppSettings["oiosaml:SqlServerSessionStoreProvider:DisableCleanup"], out disableCleanup) && disableCleanup))
            {
                _cleanupTimer = new Timer(Cleanup, null, TimeSpan.Zero, Timeout.InfiniteTimeSpan);
            }
        }

        void Cleanup(object state)
        {
            try
            {
                ExecuteSqlCommand(cmd =>
                {
                    cmd.CommandText =
                        $@"delete from {_schema}.SessionProperties where ExpiresAtUtc < @time
delete from {
                                _schema
                            }.UserAssociations where SessionId not in (select distinct SessionId from {
                                _schema
                            }.SessionProperties)";
                    cmd.Parameters.AddWithValue("@time", DateTime.UtcNow);
                    cmd.ExecuteNonQuery();
                });
            }
            catch (Exception ex)
            {
                Trace.TraceData(TraceEventType.Warning,
                    $"{nameof(SqlServerSessionStoreProvider)}: Cleanup of sessionstore failed: {ex}");
            }
            finally
            {
                _cleanupTimer.Change(_cleanupInterval, Timeout.InfiniteTimeSpan);
            }
        }

        void ISessionStoreProvider.Initialize(TimeSpan sessionTimeout, ISessionValueFactory sessionValueFactory)
        {
            _sessionTimeout = sessionTimeout;
            _sessionValueFactory = sessionValueFactory;
        }

        void ISessionStoreProvider.SetSessionProperty(Guid sessionId, string key, object value)
        {
            if (value == null) throw new ArgumentNullException(nameof(value));

            var serializedValue = _sessionValueFactory.Serialize(value);

            ExecuteSqlCommand(cmd =>
            {
                cmd.CommandText =
$@"update {_schema}.SessionProperties set 
Value = @value
where SessionId = @sessionId and [Key] = @key
if @@ROWCOUNT = 0
insert into {_schema}.SessionProperties (SessionId, [Key], ValueType, Value, ExpiresAtUtc)
values (@sessionId, @key, @valueType, @value, @expiresAtUtc);

update {_schema}.SessionProperties 
set ExpiresAtUtc = @expiresAtUtc
where sessionId = @sessionId";
                cmd.Parameters.AddWithValue("@sessionId", sessionId);
                cmd.Parameters.AddWithValue("@key", key);
                cmd.Parameters.AddWithValue("@valueType", value.GetType().AssemblyQualifiedName);
                cmd.Parameters.AddWithValue("@value", serializedValue);
                cmd.Parameters.AddWithValue("@expiresAtUtc", GetExpiresAtUtc());

                cmd.ExecuteNonQuery();
            });
        }

        private DateTime GetExpiresAtUtc()
        {
            return DateTime.UtcNow + _sessionTimeout;
        }

        void ISessionStoreProvider.RemoveSessionProperty(Guid sessionId, string key)
        {
            ExecuteSqlCommand(cmd =>
            {
                cmd.CommandText =
$@"delete from {_schema}.SessionProperties
where SessionId = @sessionId and [Key] = @key

update {_schema}.SessionProperties 
set ExpiresAtUtc = @expiresAtUtc
where sessionId = @sessionId";
                cmd.Parameters.AddWithValue("@sessionId", sessionId);
                cmd.Parameters.AddWithValue("@key", key);
                cmd.Parameters.AddWithValue("@expiresAtUtc", GetExpiresAtUtc());
                cmd.ExecuteNonQuery();
            });
        }

        object ISessionStoreProvider.GetSessionProperty(Guid sessionId, string key)
        {
            return ExecuteSqlCommand(cmd =>
            {
                cmd.CommandText =
$@"update {_schema}.SessionProperties 
set ExpiresAtUtc = @expiresAtUtc
where sessionId = @sessionId

select ValueType, Value from {_schema}.SessionProperties
where SessionId = @sessionId and [Key] = @key"; 
                cmd.Parameters.AddWithValue("@sessionId", sessionId);
                cmd.Parameters.AddWithValue("@key", key);
                cmd.Parameters.AddWithValue("@expiresAtUtc", GetExpiresAtUtc());
                using (var reader = cmd.ExecuteReader())
                {
                    if (reader.Read())
                    {

                        var valueType = (string) reader["ValueType"];
                        var value = (string) reader["Value"];

                        var type = Type.GetType(valueType);

                        if (type != null && value != null)
                        {
                            return _sessionValueFactory.Deserialize(type, value);
                        }
                    }
                }

                return null;
            });
        }

        void ISessionStoreProvider.AssociateUserIdWithSessionId(string userId, Guid sessionId)
        {
            ExecuteSqlCommand(cmd =>
            {
                cmd.CommandText =
$@"if not exists (select * from {_schema}.UserAssociations where SessionId = @sessionId and UserId = @userId)
insert into {_schema}.UserAssociations (SessionId, UserId) values (@sessionId, @userId)";
                cmd.Parameters.AddWithValue("@sessionId", sessionId);
                cmd.Parameters.AddWithValue("@userId", userId);

                cmd.ExecuteNonQuery();
            });
        }

        void ISessionStoreProvider.AbandonSessionsAssociatedWithUserId(string userId)
        {
            ExecuteSqlCommand(cmd =>
            {
                cmd.CommandText =
$@"delete from {_schema}.SessionProperties where SessionId in (select SessionId from {_schema}.UserAssociations where UserId = @userId)
delete from {_schema}.UserAssociations where UserId = @userId";
                cmd.Parameters.AddWithValue("@userId", userId);

                cmd.ExecuteNonQuery();
            });
        }

        bool ISessionStoreProvider.DoesSessionExists(Guid sessionId)
        {
            return ExecuteSqlCommand(cmd =>
            {
                cmd.CommandText =
$@"select top 1 SessionId from {_schema}.SessionProperties
where SessionId = @sessionId

update {_schema}.SessionProperties 
set ExpiresAtUtc = @expiresAtUtc
where sessionId = @sessionId;";
                cmd.Parameters.AddWithValue("@sessionid", sessionId);
                cmd.Parameters.AddWithValue("@expiresAtUtc", GetExpiresAtUtc());

                var any = cmd.ExecuteScalar();
                return any != null;
            });
        }

        void ExecuteSqlCommand(Action<SqlCommand> block)
        {
            using (var conn = new SqlConnection(_connectionString))
            {
                conn.Open();

                var cmd = conn.CreateCommand();
                block(cmd);
            }
        }

        T ExecuteSqlCommand<T>(Func<SqlCommand, T> block)
        {
            using (var conn = new SqlConnection(_connectionString))
            {
                conn.Open();

                var cmd = conn.CreateCommand();
                return block(cmd);
            }
        }
    }
}