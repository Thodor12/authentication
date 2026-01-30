
using LDTTeam.Authentication.Models.App.User;
using Wolverine;

namespace LDTTeam.Authentication.Messages.User;

            
public record ExternalLoginDisconnectedFromUser(
    Guid UserId,
    AccountProvider Provider,
    string ProviderKey,
    bool Force = false) : IMessage;