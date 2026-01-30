using System.Drawing;
using JasperFx.Core;
using LDTTeam.Authentication.DiscordBot.Model.Data;
using LDTTeam.Authentication.DiscordBot.Service;
using LDTTeam.Authentication.Messages.User;
using LDTTeam.Authentication.Models.App.Rewards;
using LDTTeam.Authentication.Models.App.User;
using Microsoft.Extensions.Logging;
using Remora.Discord.API.Objects;
using Remora.Rest.Core;
using User = LDTTeam.Authentication.DiscordBot.Model.Data.User;

namespace LDTTeam.Authentication.DiscordBot.Handlers;

public partial class UserHandler(
    IUserRepository userRepository,
    IAssignedRewardRepository assignedRewardRepository,
    DiscordRoleAssignmentService roleAssignmentService,
    DiscordEventLoggingService eventLoggingService,
    ILogger<UserHandler> logger)
{
    public async Task Handle(NewUserCreatedOrUpdated message)
    {
        var user = await userRepository.GetByIdAsync(message.Id);
        bool updated = false;
        if (user == null)
        {
            user = new User()
            {
                UserId = message.Id,
                Username = message.UserName,
                Snowflake = null
            };
            updated = true;
        }
        else
        {
            updated = user.Username != message.UserName;
            user.Username = message.UserName;
        }

        if (updated)
        {
            await userRepository.CreateOrUpdateAsync(user);
            await eventLoggingService.LogEvent(new Embed()
            {
                Title = "User Added or Updated",
                Description = $"A new user has been added: {message.UserName}",
                Colour = Color.DarkBlue,
                Fields = new[]
                {
                    new EmbedField("User ID", message.Id.ToString(), true),
                    new EmbedField("Username", message.UserName, true)
                }
            });
        }
    }

    public async Task HandleAsync(UserDeleted message)
    {
        var user = await userRepository.GetByIdAsync(message.Id);
        if (user != null)
        {
            await userRepository.DeleteAsync(message.Id);
            await eventLoggingService.LogEvent(new Embed()
            {
                Title = "User Deleted",
                Description = $"A user has been deleted: {user.Username}",
                Colour = Color.DarkRed,
                Fields = new[]
                {
                    new EmbedField("User ID", message.Id.ToString(), true),
                    new EmbedField("Username", user.Username, true)
                }
            });
        }
    }

    public async Task HandleAsync(ExternalLoginConnectedToUser message)
    {
        LogHandlingExternalloginconnectedtouserForUserIdUseridProviderProviderKey(logger, message.UserId,
            message.Provider, message.ProviderKey);

        var user = await userRepository.GetByIdAsync(message.UserId);
        if (user == null)
        {
            LogReceivedExternalloginconnectedtouserForNonExistentUserIdUserid(logger, message.UserId);
            await eventLoggingService.LogEvent(new Embed()
            {
                Title = "Login Added - User Not Found",
                Description = $"An external login was added for a user that does not exist in the database.",
                Colour = Color.Red,
                Fields = new[]
                {
                    new EmbedField("User ID", message.UserId.ToString(), true),
                    new EmbedField("Provider", message.Provider.ToString(), true),
                    new EmbedField("Provider Key", message.ProviderKey, true)
                }
            });
            return;
        }

        if (message.Provider != AccountProvider.Discord)
        {
            //No further processing just logging.
            await eventLoggingService.LogEvent(new Embed()
            {
                Title = "User Linked an External Account: " + message.Provider,
                Description = $"A new user has linked their account: {user.Username}",
                Colour = Color.GreenYellow,
                Fields = new[]
                {
                    new EmbedField("User ID", message.UserId.ToString(), true),
                    new EmbedField("Username", user.Username, true),
                    new EmbedField($"{message.Provider} ID", message.ProviderKey, true)
                }
            });
            return;
        }

        if (!Snowflake.TryParse(message.ProviderKey, out var snowflake))
        {
            LogReceivedExternalloginconnectedtouserWithInvalidSnowflakeFormatKeyForUser(logger, message.ProviderKey,
                user.UserId, user.Username);
            await eventLoggingService.LogEvent(new Embed()
            {
                Title = "Login Added - Invalid user ID",
                Description = $"An external login was added for a user that has an ID incompatible with Snowflakes.",
                Colour = Color.Red,
                Fields = new[]
                {
                    new EmbedField("User ID", user.Username, true),
                    new EmbedField("Username", user.Username, true),
                    new EmbedField("Provider Key", message.ProviderKey, true)
                }
            });
            return;
        }

        if (user.Snowflake.HasValue && user.Snowflake.Value != snowflake)
        {
            LogReceivedExternalloginconnectedtouserForUserUseridUsernameWhichWouldAlterTheSnowflake(logger, user.UserId,
                user.Username, user.Snowflake.Value, message.ProviderKey);
            await eventLoggingService.LogEvent(new Embed()
            {
                Title = "Login Added - Invalid user ID",
                Description =
                    $"An external login was added for a user which already has a different snowflake without disconnecting first.",
                Colour = Color.Red,
                Fields = new[]
                {
                    new EmbedField("User ID", user.Username, true),
                    new EmbedField("Username", user.Username, true),
                    new EmbedField("New Key", message.ProviderKey, true),
                    new EmbedField("Existing Key", user.Snowflake.Value.ToString(), true)
                }
            });
            return;
        }

        bool updated = user.Snowflake != snowflake;
        user.Snowflake = snowflake;

        LogUserIdUseridLinkedDiscordSnowflakeSnowflakeOriginalOriginalWillUpdateUpdate(logger, user.UserId, snowflake,
            user.Snowflake, updated);

        if (updated)
        {
            await userRepository.CreateOrUpdateAsync(user);

            LogUserIdUseridLinkedDiscordSnowflakeSnowflakeSavedToDatabase(logger, user.UserId, snowflake);

            var assigner = await roleAssignmentService.ForMember(user.Snowflake.Value);
            await assigner.UpdateAllRewards();

            LogUserIdUseridLinkedDiscordSnowflakeSnowflakeUpdatedRewards(logger, user.UserId, snowflake);

            await eventLoggingService.LogEvent(new Embed()
            {
                Title = "User Linked Discord",
                Description = $"A new user has linked their account: {user.Username}",
                Colour = Color.Green,
                Fields = new[]
                {
                    new EmbedField("User ID", message.UserId.ToString(), true),
                    new EmbedField("Username", user.Username, true),
                    new EmbedField("Discord ID", message.ProviderKey, true)
                }
            });
        }
    }

    public async Task Handle(ExternalLoginDisconnectedFromUser message)
    {
        var user = await userRepository.GetByIdAsync(message.UserId);
        if (user == null)
        {
            LogReceivedExternallogindisconnectedfromuserForNonExistentUserIdUserid(logger, message.UserId);

            if (message.Provider == AccountProvider.Discord)
            {
                var snowflakeUser = await userRepository.GetBySnowflakeAsync(
                    new Snowflake(ulong.Parse(message.ProviderKey))
                );

                if (snowflakeUser != null)
                {
                    LogExternallogindisconnectedfromuserForNonExistentUserIdUseridButFoundUserSnowflakeuserid(logger,
                        message.UserId, snowflakeUser.UserId, message.ProviderKey);
                    await eventLoggingService.LogEvent(new Embed()
                    {
                        Title = "Login Removed - User Not Found, Found by Snowflake",
                        Description =
                            $"An external login was removed for a user that does not exist in the database. Located user via snowflake.",
                        Colour = Color.DarkRed,
                        Fields = new[]
                        {
                            new EmbedField("Original User ID", message.UserId.ToString(), true),
                            new EmbedField("Found User ID", snowflakeUser.UserId.ToString(), true),
                            new EmbedField("Provider", message.Provider.ToString(), true),
                            new EmbedField("Provider Key", message.ProviderKey, true)
                        }
                    });
                    await Handle(message with { UserId = snowflakeUser.UserId });
                    return;
                }
            }

            await eventLoggingService.LogEvent(new Embed()
            {
                Title = "Login Removed - User Not Found",
                Description = $"An external login was removed for a user that does not exist in the database.",
                Colour = Color.Red,
                Fields = new[]
                {
                    new EmbedField("User ID", message.UserId.ToString(), true),
                    new EmbedField("Provider", message.Provider.ToString(), true),
                    new EmbedField("Provider Key", message.ProviderKey, true)
                }
            });
            return;
        }

        if (message.Provider != AccountProvider.Discord)
        {
            //No further processing just logging.
            await eventLoggingService.LogEvent(new Embed()
            {
                Title = "User Unlinked an External Account: " + message.Provider,
                Description = $"A user has unlinked their account: {user.Username}",
                Colour = Color.GreenYellow,
                Fields = new[]
                {
                    new EmbedField("User ID", message.UserId.ToString(), true),
                    new EmbedField("Username", user.Username, true),
                    new EmbedField($"{message.Provider} ID", message.ProviderKey, true)
                }
            });
            return;
        }

        if (!Snowflake.TryParse(message.ProviderKey, out var snowflake))
        {
            LogReceivedExternallogindisconnectedfromuserWithInvalidSnowflakeFormatKeyForUser(logger,
                message.ProviderKey, user.UserId, user.Username);
            await eventLoggingService.LogEvent(new Embed()
            {
                Title = "Login Removed - Invalid user ID",
                Description = $"An external login was removed for a user that has an ID incompatible with Snowflakes.",
                Colour = Color.Red,
                Fields = new[]
                {
                    new EmbedField("User ID", user.Username, true),
                    new EmbedField("Username", user.Username, true),
                    new EmbedField("Provider Key", message.ProviderKey, true)
                }
            });
            return;
        }

        if (!user.Snowflake.HasValue || user.Snowflake.Value != snowflake)
        {
            LogReceivedExternallogindisconnectedfromuserForUserUseridUsernameWhichDoesNotMatchThe(logger, user.UserId,
                user.Username, user.Snowflake?.ToString() ?? "null");
            await eventLoggingService.LogEvent(new Embed()
            {
                Title = "Login Removed - Invalid user ID",
                Description = $"An external login was removed for a user with a different or none existent connection.",
                Colour = Color.Red,
                Fields = new[]
                {
                    new EmbedField("User ID", user.Username, true),
                    new EmbedField("Username", user.Username, true),
                    new EmbedField("New Key", message.ProviderKey, true),
                    new EmbedField("Existing Key", user.Snowflake?.Value.ToString() ?? "Not set", true)
                }
            });

            logger.LogCritical(
                "ExternalLoginDisconnectedFromUser for non-existent user ID {UserId} but found user {SnowflakeUserId} by snowflake {ProviderKey}. Forcing removal!",
                message.UserId, user.UserId, message.ProviderKey);

            var snowflakeUser = await userRepository.GetBySnowflakeAsync(
                new Snowflake(ulong.Parse(message.ProviderKey))
            );

            if (snowflakeUser != null)
            {
                LogExternallogindisconnectedfromuserForNonExistentUserIdUseridButFoundUserSnowflakeuserid(
                    logger, message.UserId, snowflakeUser.UserId, message.ProviderKey);
                await eventLoggingService.LogEvent(new Embed()
                {
                    Title = "Login Removed - User Mismatch, Found by Snowflake",
                    Description =
                        $"An external login was removed for a user that has a different or none existent connection. Located user via snowflake.",
                    Colour = Color.DarkRed,
                    Fields = new[]
                    {
                        new EmbedField("Original User ID", message.UserId.ToString(), true),
                        new EmbedField("Found User ID", snowflakeUser.UserId.ToString(), true),
                        new EmbedField("Provider", message.Provider.ToString(), true),
                        new EmbedField("Provider Key", message.ProviderKey, true)
                    }
                });
                await Handle(message with { UserId = snowflakeUser.UserId });
                return;
            }
            
            return;
        }

        var userId = user.Snowflake.Value;
        user.Snowflake = null;
        await userRepository.CreateOrUpdateAsync(user);

        var assigner = await roleAssignmentService.ForMember(userId);
        await assigner.RemoveAllRewards();

        await eventLoggingService.LogEvent(new Embed()
        {
            Title = "User Unlinked Discord",
            Description = $"A user has unlinked their account: {user.Username}",
            Colour = Color.DarkOrange,
            Fields = new[]
            {
                new EmbedField("User ID", message.UserId.ToString(), true),
                new EmbedField("Username", user.Username, true),
                new EmbedField("Discord ID", message.ProviderKey, true)
            }
        });
    }

    public async Task Handle(UserRewardAdded message)
    {
        var user = await userRepository.GetByIdAsync(message.UserId);
        if (user == null)
        {
            LogReceivedUserrewardaddedForNonExistentUserIdUserid(logger, message.UserId);
            await eventLoggingService.LogEvent(new Embed()
            {
                Title = "Reward Added - User Not Found",
                Description =
                    $"An reward was added for a user that does not exist in the database. It will be added later when they register.",
                Colour = Color.OrangeRed,
                Fields = new[]
                {
                    new EmbedField("User ID", message.UserId.ToString(), true),
                    new EmbedField("Reward", message.Reward, true),
                    new EmbedField("Type", message.RewardType.ToString(), true)
                }
            });
            return;
        }

        await assignedRewardRepository.AssignAsync(new AssignedReward()
        {
            UserId = message.UserId,
            Reward = message.Reward,
            Type = message.RewardType
        });

        if (!user?.Snowflake.HasValue ?? false)
        {
            LogReceivedUserrewardaddedForUserIdUseridWhichHasNoDiscordLinkedAccount(logger, message.UserId);
            await eventLoggingService.LogEvent(new Embed()
            {
                Title = "Reward Added - No Discord Linked",
                Description =
                    $"An reward was added for a user that has not linked their Discord account. It will be added later when they link their accounts.",
                Colour = Color.Orange,
                Fields = new[]
                {
                    new EmbedField("User ID", message.UserId.ToString(), true),
                    new EmbedField("Username", user.Username, true),
                    new EmbedField("Reward", message.Reward, true),
                    new EmbedField("Type", message.RewardType.ToString(), true)
                }
            });
            return;
        }

        if (user?.Snowflake.HasValue ?? false)
        {
            var assigner = await roleAssignmentService.ForMember(user.Snowflake.Value);
            await assigner.EnsureRewardsAssigned();

            await eventLoggingService.LogEvent(new Embed()
            {
                Title = "Reward Assigned",
                Description = $"The rewards for user: {user.Username} have been updated.",
                Colour = Color.Green,
                Fields = new[]
                {
                    new EmbedField("User ID", message.UserId.ToString(), true),
                    new EmbedField("Username", user.Username, true),
                    new EmbedField("Reward", message.Reward, true),
                    new EmbedField("Type", message.RewardType.ToString(), true)
                }
            });
        }

        LogAssignedRewardRewardOfTypeTypeToUserIdUserid(logger, message.Reward, message.RewardType, message.UserId);
    }

    public async Task Handle(UserRewardRemoved message)
    {
        var user = await userRepository.GetByIdAsync(message.UserId);
        if (user == null)
        {
            LogReceivedUserrewardremovedForNonExistentUserIdUserid(logger, message.UserId);
            await eventLoggingService.LogEvent(new Embed()
            {
                Title = "Reward Removed - User Not Found",
                Description =
                    $"An reward was removed for a user that does not exist in the database. It will not be assigned later when they register.",
                Colour = Color.OrangeRed,
                Fields = new[]
                {
                    new EmbedField("User ID", message.UserId.ToString(), true),
                    new EmbedField("Reward", message.Reward, true),
                    new EmbedField("Type", message.RewardType.ToString(), true)
                }
            });
            return;
        }

        if (!user?.Snowflake.HasValue ?? false)
        {
            LogReceivedUserrewardremovedForUserIdUseridWhichHasNoDiscordLinkedAccount(logger, message.UserId);
            await eventLoggingService.LogEvent(new Embed()
            {
                Title = "Reward Removed - No Discord Linked",
                Description =
                    $"An reward was removed for a user that has not linked their Discord account. It will not be added later when they link their accounts.",
                Colour = Color.Orange,
                Fields = new[]
                {
                    new EmbedField("User ID", message.UserId.ToString(), true),
                    new EmbedField("Username", user.Username, true),
                    new EmbedField("Reward", message.Reward, true),
                    new EmbedField("Type", message.RewardType.ToString(), true)
                }
            });
            return;
        }

        await assignedRewardRepository.RemoveAsync(message.UserId, message.Reward, message.RewardType);

        if (user?.Snowflake.HasValue ?? false)
        {
            var assigner = await roleAssignmentService.ForMember(user.Snowflake.Value);
            await assigner.UpdateAllRewards();

            await eventLoggingService.LogEvent(new Embed()
            {
                Title = "Reward Removed",
                Description = $"The rewards for user: {user.Username} have been updated.",
                Colour = Color.DarkGreen,
                Fields = new[]
                {
                    new EmbedField("User ID", message.UserId.ToString(), true),
                    new EmbedField("Username", user.Username, true),
                    new EmbedField("Reward", message.Reward, true),
                    new EmbedField("Type", message.RewardType.ToString(), true)
                }
            });
        }

        LogUnassignedRewardRewardOfTypeTypeToUserIdUserid(logger, message.Reward, message.RewardType, message.UserId);
    }

    [LoggerMessage(LogLevel.Error, "Received ExternalLoginConnectedToUser for non-existent user ID {userId}")]
    static partial void LogReceivedExternalloginconnectedtouserForNonExistentUserIdUserid(ILogger<UserHandler> logger,
        Guid userId);

    [LoggerMessage(LogLevel.Error,
        "Received ExternalLoginConnectedToUser with invalid snowflake format: {key}, for user: {userId}/{userName}")]
    static partial void LogReceivedExternalloginconnectedtouserWithInvalidSnowflakeFormatKeyForUser(
        ILogger<UserHandler> logger, string key, Guid userId, string userName);

    [LoggerMessage(LogLevel.Error,
        "Received ExternalLoginConnectedToUser for user: {userId}/{userName}, which would alter the Snowflake from: {oldId} to {newId}")]
    static partial void LogReceivedExternalloginconnectedtouserForUserUseridUsernameWhichWouldAlterTheSnowflake(
        ILogger<UserHandler> logger, Guid userId, string userName, Snowflake oldId, string newId);

    [LoggerMessage(LogLevel.Error, "Received UserRewardAdded for non-existent user ID {userId}")]
    static partial void LogReceivedUserrewardaddedForNonExistentUserIdUserid(ILogger<UserHandler> logger, Guid userId);

    [LoggerMessage(LogLevel.Warning,
        "Received UserRewardAdded for user ID {userId} which has no Discord linked account")]
    static partial void LogReceivedUserrewardaddedForUserIdUseridWhichHasNoDiscordLinkedAccount(
        ILogger<UserHandler> logger, Guid userId);

    [LoggerMessage(LogLevel.Information, "Assigned reward {reward} of type {type} to user ID {userId}")]
    static partial void LogAssignedRewardRewardOfTypeTypeToUserIdUserid(ILogger<UserHandler> logger, string reward,
        RewardType type, Guid userId);

    [LoggerMessage(LogLevel.Error, "Received UserRewardRemoved for non-existent user ID {userId}")]
    static partial void
        LogReceivedUserrewardremovedForNonExistentUserIdUserid(ILogger<UserHandler> logger, Guid userId);

    [LoggerMessage(LogLevel.Warning,
        "Received UserRewardRemoved for user ID {userId} which has no Discord linked account")]
    static partial void LogReceivedUserrewardremovedForUserIdUseridWhichHasNoDiscordLinkedAccount(
        ILogger<UserHandler> logger, Guid userId);

    [LoggerMessage(LogLevel.Information, "Unassigned reward {reward} of type {type} to user ID {userId}")]
    static partial void LogUnassignedRewardRewardOfTypeTypeToUserIdUserid(ILogger<UserHandler> logger, string reward,
        RewardType type, Guid userId);

    [LoggerMessage(LogLevel.Error, "Received ExternalLoginDisconnectedFromUser for non-existent user ID {userId}")]
    static partial void LogReceivedExternallogindisconnectedfromuserForNonExistentUserIdUserid(
        ILogger<UserHandler> logger, Guid userId);

    [LoggerMessage(LogLevel.Error,
        "Received ExternalLoginDisconnectedFromUser with invalid snowflake format: {key}, for user: {userId}/{userName}")]
    static partial void LogReceivedExternallogindisconnectedfromuserWithInvalidSnowflakeFormatKeyForUser(
        ILogger<UserHandler> logger, string key, Guid userId, string userName);

    [LoggerMessage(LogLevel.Error,
        "Received ExternalLoginDisconnectedFromUser for user: {userId}/{userName}, which does not match the stored Snowflake: {storedId}")]
    static partial void LogReceivedExternallogindisconnectedfromuserForUserUseridUsernameWhichDoesNotMatchThe(
        ILogger<UserHandler> logger, Guid userId, string userName, string storedId);

    [LoggerMessage(LogLevel.Warning,
        "Handling ExternalLoginConnectedToUser for User ID: {UserId}, Provider: {Provider}, Key: {ProviderKey}")]
    static partial void LogHandlingExternalloginconnectedtouserForUserIdUseridProviderProviderKey(
        ILogger<UserHandler> logger, Guid UserId, AccountProvider Provider, string ProviderKey);

    [LoggerMessage(LogLevel.Information,
        "User ID: {UserId} linked Discord Snowflake: {Snowflake}. Original {Original}, will update: {Update}")]
    static partial void LogUserIdUseridLinkedDiscordSnowflakeSnowflakeOriginalOriginalWillUpdateUpdate(
        ILogger<UserHandler> logger, Guid UserId, Snowflake? Snowflake, Snowflake? Original, bool Update);

    [LoggerMessage(LogLevel.Information, "User ID: {UserId} linked Discord Snowflake: {Snowflake}. Saved to database")]
    static partial void LogUserIdUseridLinkedDiscordSnowflakeSnowflakeSavedToDatabase(ILogger<UserHandler> logger,
        Guid UserId, Snowflake? Snowflake);

    [LoggerMessage(LogLevel.Information, "User ID: {UserId} linked Discord Snowflake: {Snowflake}. Updated rewards")]
    static partial void LogUserIdUseridLinkedDiscordSnowflakeSnowflakeUpdatedRewards(ILogger<UserHandler> logger,
        Guid UserId, Snowflake? Snowflake);

    [LoggerMessage(LogLevel.Critical,
        "ExternalLoginDisconnectedFromUser for non-existent user ID {UserId} but found user {SnowflakeUserId} by snowflake {ProviderKey}")]
    static partial void LogExternallogindisconnectedfromuserForNonExistentUserIdUseridButFoundUserSnowflakeuserid(
        ILogger<UserHandler> logger, Guid UserId, Guid SnowflakeUserId, string ProviderKey);
}