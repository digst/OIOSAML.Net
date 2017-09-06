--Must be run manually against the target database.
--if custom schema is used via the 'oiosaml:SqlServerSessionStoreProvider:Schema' setting, the schema in this script must be edited before applying

USE OIOSAML; -- Change name to the name of the target database.

CREATE TABLE [dbo].[SessionProperties](
	[SessionId] [uniqueidentifier] NOT NULL,
	[Key] [nvarchar](100) NOT NULL,
	[ValueType] [nvarchar](500) NULL,
	[Value] [nvarchar](max) NULL,
	[ExpiresAtUtc] [datetime] NULL,
 CONSTRAINT [PK_SessionProperties] PRIMARY KEY CLUSTERED 
(
	[SessionId] ASC,
	[Key] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

GO

CREATE TABLE [dbo].[UserAssociations](
	[SessionId] [uniqueidentifier] NOT NULL,
	[UserId] [nvarchar](300) NOT NULL,
 CONSTRAINT [PK_UserAssociations] PRIMARY KEY CLUSTERED 
(
	[SessionId] ASC,
	[UserId] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

GO