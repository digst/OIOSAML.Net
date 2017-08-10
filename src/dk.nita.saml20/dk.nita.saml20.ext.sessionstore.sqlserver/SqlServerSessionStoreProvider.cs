using System;
using System.Configuration;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Threading;
using dk.nita.saml20.Session;
using Trace = dk.nita.saml20.Utils.Trace;

namespace dk.nita.saml20.ext.sessionstore.sqlserver
{
    public class SqlServerSessionStoreProvider : ISessionStoreProvider
    {
        private readonly string _connectionString;
        private readonly string _schema;
        private TimeSpan _sessionTimeout;
        private readonly Timer _cleanupTimer;
        private readonly TimeSpan _cleanupInterval = TimeSpan.FromMinutes(1);
        private ISessionValueFactory _sessionValueFactory;

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

        private void Cleanup(object state)
        {
            try
            {
                ExecuteSqlCommand(cmd =>
                {
                    cmd.CommandText =
                        $@"delete from {_schema}.SessionProperties where ExpiresAt < @time
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
                Trace.TraceData(TraceEventType.Error,
                    $"{nameof(SqlServerSessionStoreProvider)}: Cleanup of sessionstore failed: {ex}");
            }
            finally
            {
                _cleanupTimer.Change(_cleanupInterval, Timeout.InfiniteTimeSpan);
            }
        }

        public void Initialize(TimeSpan sessionTimeout, ISessionValueFactory sessionValueFactory)
        {
            _sessionTimeout = sessionTimeout;
            _sessionValueFactory = sessionValueFactory;
        }

        public void SetSessionProperty(Guid sessionId, string key, object value)
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
insert into {_schema}.SessionProperties (SessionId, [Key], ValueType, Value, ExpiresAt)
values (@sessionId, @key, @valueType, @value, @expiresAt);

update {_schema}.SessionProperties 
set ExpiresAt = @expiresAt
where sessionId = @sessionId";
                cmd.Parameters.AddWithValue("@sessionId", sessionId);
                cmd.Parameters.AddWithValue("@key", key);
                cmd.Parameters.AddWithValue("@valueType", value.GetType().AssemblyQualifiedName);
                cmd.Parameters.AddWithValue("@value", serializedValue);
                cmd.Parameters.AddWithValue("@expiresAt", GetExpiresAt());

                cmd.ExecuteNonQuery();
            });
        }

        private DateTime GetExpiresAt()
        {
            return DateTime.UtcNow + _sessionTimeout;
        }

        public void RemoveSessionProperty(Guid sessionId, string key)
        {
            ExecuteSqlCommand(cmd =>
            {
                cmd.CommandText =
$@"delete from {_schema}.SessionProperties
where SessionId = @sessionId and [Key] = @key

update {_schema}.SessionProperties 
set ExpiresAt = @expiresAt
where sessionId = @sessionId";
                cmd.Parameters.AddWithValue("@sessionId", sessionId);
                cmd.Parameters.AddWithValue("@key", key);
                cmd.Parameters.AddWithValue("@expiresAt", GetExpiresAt());
                cmd.ExecuteNonQuery();
            });
        }

        public object GetSessionProperty(Guid sessionId, string key)
        {
            return ExecuteSqlCommand(cmd =>
            {
                cmd.CommandText =
$@"update {_schema}.SessionProperties 
set ExpiresAt = @expiresAt
where sessionId = @sessionId

select ValueType, Value from {_schema}.SessionProperties
where SessionId = @sessionId and [Key] = @key"; 
                cmd.Parameters.AddWithValue("@sessionId", sessionId);
                cmd.Parameters.AddWithValue("@key", key);
                cmd.Parameters.AddWithValue("@expiresAt", GetExpiresAt());
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

        public void AssociateUserIdWithSessionId(string userId, Guid sessionId)
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

        public void AbandonSessionsAssociatedWithUserId(string userId)
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