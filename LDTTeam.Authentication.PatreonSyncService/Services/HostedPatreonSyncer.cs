using LDTTeam.Authentication.Messages.User;
using LDTTeam.Authentication.Models.App.User;
using LDTTeam.Authentication.PatreonApiUtils.Messages;
using LDTTeam.Authentication.PatreonApiUtils.Service;

namespace LDTTeam.Authentication.PatreonSyncService.Services;

public class HostedPatreonSyncer(
    IPatreonMembershipService membershipService,
    IHostApplicationLifetime lifecycleService,
    ILogger<HostedPatreonSyncer> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("Starting Patreon membership synchronization...");
        await membershipService.UpdateAllStatuses();
        
        logger.LogInformation("Patreon membership synchronization complete. Stopping application...");
        lifecycleService.StopApplication();
    }
}