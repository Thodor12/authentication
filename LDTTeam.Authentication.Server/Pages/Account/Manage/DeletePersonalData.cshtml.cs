using System;
using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;
using LDTTeam.Authentication.Messages.User;
using LDTTeam.Authentication.Models.App.User;
using LDTTeam.Authentication.Modules.Api;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Wolverine;
using Wolverine.Runtime.Batching;

namespace LDTTeam.Authentication.Server.Pages.Account.Manage
{
    [Authorize]
    public class DeletePersonalDataModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<DeletePersonalDataModel> _logger;
        private readonly IMessageBus _bus;

        public DeletePersonalDataModel(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            ILogger<DeletePersonalDataModel> logger,
            IMessageBus bus)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
            _bus = bus;
        }

        [BindProperty]
        public InputModel Input { get; set; }

        public class InputModel
        {
            [Required]
            [DataType(DataType.Password)]
            public string Password { get; set; }
        }

        public bool RequirePassword { get; set; }

        public async Task<IActionResult> OnGet()
        {
            ApplicationUser user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            RequirePassword = await _userManager.HasPasswordAsync(user);
            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            ApplicationUser user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            RequirePassword = await _userManager.HasPasswordAsync(user);
            if (RequirePassword)
            {
                if (!await _userManager.CheckPasswordAsync(user, Input.Password))
                {
                    ModelState.AddModelError(string.Empty, "Incorrect password.");
                    return Page();
                }
            }

            var logins = await _userManager.GetLoginsAsync(user);
            foreach (var userLoginInfo in logins)
            {
                await _bus.PublishAsync(new ExternalLoginDisconnectedFromUser(
                    Guid.Parse(user.Id),
                    Enum.Parse<AccountProvider>(userLoginInfo.LoginProvider),
                    userLoginInfo.ProviderKey,
                    true
                ));
            }
            
            IdentityResult result = await _userManager.DeleteAsync(user);
            string userId = await _userManager.GetUserIdAsync(user);
            if (!result.Succeeded)
            {
                throw new InvalidOperationException($"Unexpected error occurred deleting user with ID '{userId}'.");
            }

            await _bus.PublishAsync(new UserDeleted(Guid.Parse(userId)));
            
            await _signInManager.SignOutAsync();

            _logger.LogInformation("User with ID '{UserId}' deleted themselves.", userId);

            return Redirect("~/");
        }
    }
}
